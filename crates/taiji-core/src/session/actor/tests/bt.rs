/// v2-only metainfo builder (same fixture shape as
/// corruption_injection; 64KiB pieces x 2 = 128KiB single file). The
/// file name is fixed to `v2.bin` — tests that place multiple tasks in
/// one dir must use [`build_v2_torrent_named`] to give each task a
/// unique name (same-dest exclusivity: a different infohash with the
/// same dir+name = acceptance rejection).
fn build_v2_torrent(content: &[u8], announce: &str) -> Vec<u8> {
    build_v2_torrent_opts(content, Some(announce))
}

/// v2-only builder with an explicit file name (the unique-name face
/// for multi-task-same-dir tests).
fn build_v2_torrent_named(content: &[u8], announce: &str, name: &str) -> Vec<u8> {
    build_v2_torrent_opts_named(content, Some(announce), name)
}

/// Trackerless fixture: no top-level announce key (the metadata shape
/// the intake gate branches on: the DHT-on arm accepts, the DHT-off
/// arm rejects).
fn build_v2_torrent_trackerless(content: &[u8]) -> Vec<u8> {
    build_v2_torrent_opts(content, None)
}

/// Trackerless fixture with an explicit file name (the unique-name
/// face for same-dest-exclusive multi-task tests).
fn build_v2_torrent_trackerless_named(content: &[u8], name: &str) -> Vec<u8> {
    build_v2_torrent_opts_named(content, None, name)
}

/// v2-only builder core (announce = None -> both announce and
/// announce-list absent; the empty-string sentinel shape). The file
/// name is fixed to `v2.bin`.
fn build_v2_torrent_opts(content: &[u8], announce: Option<&str>) -> Vec<u8> {
    build_v2_torrent_opts_named(content, announce, "v2.bin")
}

/// BEP12 multi-tier fixture: announce-list only at the top level (no
/// announce key), URLs kept in order within a tier.
fn build_v2_torrent_multi_tier(content: &[u8], tiers: &[&[&str]]) -> Vec<u8> {
    build_v2_torrent_full_named(content, None, Some(tiers), "v2.bin")
}

/// v2-only builder core (parameterized file-name shape).
fn build_v2_torrent_opts_named(content: &[u8], announce: Option<&str>, name: &str) -> Vec<u8> {
    build_v2_torrent_full_named(content, announce, None, name)
}

/// v2-only builder core (full-parameter shape: top-level announce and
/// announce-list each optional; BEP12 coexistence of the two keys).
fn build_v2_torrent_full_named(
    content: &[u8],
    announce: Option<&str>,
    announce_list: Option<&[&[&str]]>,
    name: &str,
) -> Vec<u8> {
    const P: u64 = 64 * 1024;
    const BLOCK: u64 = 16 * 1024;
    let bpp = (P / BLOCK) as usize;
    let piece_roots: Vec<[u8; 32]> = content
        .chunks(P as usize)
        .map(|c| {
            let blocks: Vec<[u8; 32]> = c.chunks(BLOCK as usize).map(merkle::block_hash).collect();
            merkle::root_from_block_hashes(&blocks)
        })
        .collect();
    let root = merkle::file_root_from_piece_roots(&piece_roots, bpp);
    let mut layer = Vec::new();
    for r in &piece_roots {
        layer.extend_from_slice(r);
    }
    // BEP52 file tree: the path node = { "": {length, pieces root} }.
    let file_entry = Value::Dict(
        vec![(
            b"".to_vec(),
            Value::Dict(
                vec![
                    (b"length".to_vec(), Value::Int(content.len() as i64)),
                    (b"pieces root".to_vec(), Value::Bytes(root.to_vec())),
                ]
                .into_iter()
                .collect(),
            ),
        )]
        .into_iter()
        .collect(),
    );
    let info = Value::Dict(
        vec![
            (
                b"file tree".to_vec(),
                Value::Dict(
                    vec![(name.as_bytes().to_vec(), file_entry)]
                        .into_iter()
                        .collect(),
                ),
            ),
            (b"meta version".to_vec(), Value::Int(2)),
            (b"piece length".to_vec(), Value::Int(P as i64)),
        ]
        .into_iter()
        .collect(),
    );
    let mut top_pairs: Vec<(Vec<u8>, Value)> = Vec::new();
    if let Some(announce) = announce {
        top_pairs.push((
            b"announce".to_vec(),
            Value::Bytes(announce.as_bytes().to_vec()),
        ));
    }
    if let Some(tiers) = announce_list {
        top_pairs.push((
            b"announce-list".to_vec(),
            Value::List(
                tiers
                    .iter()
                    .map(|urls| {
                        Value::List(
                            urls.iter()
                                .map(|u| Value::Bytes(u.as_bytes().to_vec()))
                                .collect(),
                        )
                    })
                    .collect(),
            ),
        ));
    }
    top_pairs.push((b"info".to_vec(), info));
    top_pairs.push((
        b"piece layers".to_vec(),
        Value::Dict(
            vec![(root.to_vec(), Value::Bytes(layer))]
                .into_iter()
                .collect(),
        ),
    ));
    let top = Value::Dict(top_pairs);
    bencode::encode(&top).unwrap_or_else(|e| panic!("{e}"))
}

/// Unreachable tracker (port 1 -> immediate connection refusal): the
/// engine still starts and the shutdown stopped sequence completes
/// quickly, so tests have no external dependencies.
fn dead_tracker() -> String {
    "http://127.0.0.1:1/announce".to_string()
}

/// Trackerless + DHT on (session default) -> addTorrent accepted and
/// the task enters pure-DHT discovery (empty tiers + the engine DHT
/// face; the real-swarm completion face belongs to the server rerun
/// e2e — this test locks the intake acceptance face).
#[tokio::test]
async fn add_torrent_trackerless_with_dht_on_is_accepted() {
    let (handle, join) = SessionActor::spawn();
    let dir = temp_dir("trackerless-dht-on");
    let bytes = build_v2_torrent_trackerless(&vec![7u8; 128 * 1024]);
    let gid = gid_of(&call(&handle, torrent_cmd(bytes, &dir)).await);
    // Visible in tellActive (acceptance immediately activates the
    // placeholder; discovery source = pure DHT, no tracker).
    let active = status_list(&call(&handle, SessionCommand::TellActive { keys: vec![] }).await);
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].gid, gid);
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(1), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// Same-dest (dir+name) exclusivity for two BT tasks. When two tasks
/// with different infohashes have dests pointing at the same path
/// (multi-file = same content root, single-file = same data file), two
/// VerifiedWriters would each pwrite their own torrent's verified
/// bytes into the same data file = real data corruption; the spill
/// face shares `<task>/face<N>` and the writers delete each other's
/// in-flight pieces. The HTTP face closes the same race with the
/// `.part` occupancy table (`taiji.http.path_conflict`); the BT face's
/// addTorrent acceptance point must reject the second add
/// (path_conflict semantics).
#[tokio::test]
async fn add_torrent_same_dest_second_add_rejected_path_conflict() {
    let (handle, join) = SessionActor::spawn();
    let dir = temp_dir("sec27-dest");
    // Different content -> different infohash; same file name (v2.bin)
    // + same dir -> same dest.
    let first_bytes = build_v2_torrent_trackerless(&vec![7u8; 128 * 1024]);
    let gid = gid_of(&call(&handle, torrent_cmd(first_bytes, &dir)).await);
    let second_bytes = build_v2_torrent_trackerless(&vec![9u8; 128 * 1024]);
    match call(&handle, torrent_cmd(second_bytes, &dir)).await {
        Err(SessionError::Failed { message }) => {
            assert!(
                message.contains("path_conflict"),
                "error shape aligned with the HTTP path_conflict semantics: {message}"
            );
        }
        other => panic!("second add on same dest must be rejected, got {other:?}"),
    }
    // The first task is unaffected (still active).
    let active = status_list(&call(&handle, SessionCommand::TellActive { keys: vec![] }).await);
    assert!(
        active.iter().any(|s| s.gid == gid),
        "first task unaffected by rejected second add"
    );
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(1), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// Flip: trackerless + DHT off -> accepted (the task enters the
/// activation face = the stalled-discovery-source shape; the WARN-copy
/// assertion is locked in both arms of
/// `metainfo::tests::trackerless_intake_gate_conditional`) ->
/// `changeGlobalOption enable-dht=true` hot-update accepted + the echo
/// flips (session-level hot-switch plumbing; hot-push to a running
/// engine = the engine-face e2e in tests/dht_wire.rs). Reproduction
/// sequence: accept a trackerless task with the session off ->
/// hot-enable -> no restart.
#[tokio::test]
async fn add_torrent_trackerless_with_dht_off_is_accepted_then_hot_enabled() {
    let global = GlobalOptions {
        enable_dht: false,
        ..Default::default()
    };
    let (handle, join) = SessionActor::spawn_with(SessionOptions { global });
    let dir = temp_dir("trackerless-dht-off");
    let bytes = build_v2_torrent_trackerless(&vec![7u8; 128 * 1024]);
    // Acceptance arm: the task exists and is active (the
    // stalled-discovery-source shape — no longer the rejection face).
    let gid = gid_of(&call(&handle, torrent_cmd(bytes, &dir)).await);
    let active = status_list(&call(&handle, SessionCommand::TellActive { keys: vec![] }).await);
    assert_eq!(
        active.len(),
        1,
        "DHT off + no tracker = accepted (stalled shape)"
    );
    assert_eq!(active[0].gid, gid);
    // Hot-enable arm: changeGlobalOption accepted + echo flips (the
    // hot-switch value face).
    let flip = SessionCommand::ChangeGlobalOption {
        options: [("enable-dht".to_string(), "true".to_string())]
            .into_iter()
            .collect(),
    };
    assert!(matches!(
        call(&handle, flip).await,
        Ok(CommandReply::Accepted)
    ));
    match call(&handle, SessionCommand::GetGlobalOption).await {
        Ok(CommandReply::Options(echo)) => {
            assert_eq!(
                echo.get("enable-dht").map(String::as_str),
                Some("true"),
                "echo flips after hot enable"
            );
        }
        other => panic!("GetGlobalOption: {other:?}"),
    }
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// Per-task flag, two arms (session face): two trackerless tasks in
/// one session — (1) add carrying `bt-disable-dht=true` (the add-face
/// acceptance arm) and (2) the changeOption hot-update arm — each takes
/// effect and neither affects the other: the target task's getOption
/// echoes "true" while the other task has no key (follows the session —
/// no fabricated baseline). The session enable-dht flip is accepted on
/// both arms (hot-switch plumbing; engine-face linkage = the
/// tests/dht_wire.rs hot-switch e2e; the synthetic face of tasks not
/// being dragged along is carried by the effective_task_dht single
/// point + the engine SetDhtEnabled idempotent gate).
#[tokio::test]
async fn per_task_bt_disable_dht_flag_is_scoped_to_single_task() {
    let (handle, join) = SessionActor::spawn();
    let dir = temp_dir("bt-disable-dht-scoped");
    // The two tasks need distinct identities (identity dedup face) —
    // built with heterogeneous content.
    let bytes_a = build_v2_torrent_trackerless(&vec![7u8; 128 * 1024]);
    let bytes_b = build_v2_torrent_trackerless_named(&vec![9u8; 192 * 1024], "v2-b.bin");
    // Task A: explicit add-face override (true).
    let cmd_a = SessionCommand::AddTorrent {
        torrent: bytes_a,
        options: BTreeMap::from([
            ("dir".to_string(), dir.display().to_string()),
            ("bt-disable-dht".to_string(), "true".to_string()),
        ]),
        position: None,
    };
    let a = gid_of(&call(&handle, cmd_a).await);
    // Task B: not carried on the add face (follows the session).
    let b = gid_of(&call(&handle, torrent_cmd(bytes_b, &dir)).await);
    assert_ne!(a, b);
    // Echo both arms: A = "true"; B = key absent (follows the session).
    async fn echo_of(handle: &SessionHandle, g: Gid) -> BTreeMap<String, String> {
        match call(handle, SessionCommand::GetOption { gid: g.to_string() }).await {
            Ok(CommandReply::Options(echo)) => echo,
            other => panic!("getOption: {other:?}"),
        }
    }
    assert_eq!(
        echo_of(&handle, a)
            .await
            .get("bt-disable-dht")
            .map(String::as_str),
        Some("true"),
        "task A's explicit override must echo"
    );
    assert!(
        !echo_of(&handle, b).await.contains_key("bt-disable-dht"),
        "task B without the key does not echo (follows the session face)"
    );
    // changeOption hot-update arm: B explicitly flips to false (force
    // on) -> echo flips; A unaffected.
    let co = SessionCommand::ChangeOption {
        gid: b.to_string(),
        options: [("bt-disable-dht".to_string(), "false".to_string())]
            .into_iter()
            .collect(),
    };
    assert!(matches!(
        call(&handle, co).await,
        Ok(CommandReply::Accepted)
    ));
    assert_eq!(
        echo_of(&handle, b)
            .await
            .get("bt-disable-dht")
            .map(String::as_str),
        Some("false"),
        "the changeOption hot-update arm flips the echo"
    );
    assert_eq!(
        echo_of(&handle, a)
            .await
            .get("bt-disable-dht")
            .map(String::as_str),
        Some("true"),
        "task A's flag is unaffected by B's changeOption (per-task scope)"
    );
    // Session-level flip accepted on both arms (value face; per-task
    // overrides are not dragged along = the synthetic-face single
    // point).
    let flip = SessionCommand::ChangeGlobalOption {
        options: [("enable-dht".to_string(), "false".to_string())]
            .into_iter()
            .collect(),
    };
    assert!(matches!(
        call(&handle, flip).await,
        Ok(CommandReply::Accepted)
    ));
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// Magnet without tr: after acceptance the task ends on the
/// explicit-failure face (an Error result) rather than pretending to
/// be completable (the DHT lease wiring is closed out with the shared
/// services).
#[tokio::test]
async fn magnet_without_trackers_fails_explicitly_after_activation() {
    let (handle, join) = SessionActor::spawn();
    let magnet = SessionCommand::AddUri {
        uris: vec!["magnet:?xt=urn:btih:1111111111111111111111111111111111111111".into()],
        options: BTreeMap::new(),
        position: None,
    };
    let gid = gid_of(&call(&handle, magnet).await);
    let mut err_status = false;
    for _ in 0..100 {
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
        if stopped
            .iter()
            .any(|v| v.gid == gid && v.status == StatusKind::Error)
        {
            err_status = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        err_status,
        "no-tr magnet must end with explicit Error result"
    );
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(1), join).await;
}

// ---- Query face: local-seeder closed-loop download field snapshot ----

const SEED_PIECE_LEN: u64 = 16384;

fn seed_content() -> Vec<u8> {
    const P: &[u8] = b"taiji-p35-query-";
    P.iter()
        .cycle()
        .take(2 * SEED_PIECE_LEN as usize)
        .copied()
        .collect()
}

/// Downloadable v1 metainfo (pieces = real SHA-1; announce points at
/// the local fake tracker).
fn downloadable_v1_torrent(content: &[u8], announce: &str, name: &str) -> Vec<u8> {
    use sha1::{Digest as _, Sha1 as _Sha1};
    let mut pieces = Vec::new();
    for c in content.chunks(SEED_PIECE_LEN as usize) {
        pieces.extend_from_slice(&_Sha1::digest(c));
    }
    let info = Value::Dict(
        vec![
            (b"length".to_vec(), Value::Int(content.len() as i64)),
            (b"name".to_vec(), Value::Bytes(name.as_bytes().to_vec())),
            (b"piece length".to_vec(), Value::Int(SEED_PIECE_LEN as i64)),
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
            (b"comment".to_vec(), Value::Bytes(b"p35 snapshot".to_vec())),
            (b"creation date".to_vec(), Value::Int(1700000000)),
            (b"info".to_vec(), info),
        ]
        .into_iter()
        .collect(),
    );
    bencode::encode(&top).unwrap_or_else(|e| panic!("{e}"))
}

/// Fake tracker: every announce replies with compact peers = the
/// mini-seeder address.
async fn loopback_tracker(seeder_addr: std::net::SocketAddr) -> std::net::SocketAddr {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
    let addr = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            let std::net::IpAddr::V4(v4) = seeder_addr.ip() else {
                panic!("expects IPv4");
            };
            let mut peers = Vec::new();
            peers.extend_from_slice(&v4.octets());
            peers.extend_from_slice(&seeder_addr.port().to_be_bytes());
            let mut raw = Vec::new();
            raw.extend_from_slice(b"d8:intervali60e5:peers");
            raw.extend_from_slice(peers.len().to_string().as_bytes());
            raw.push(b':');
            raw.extend_from_slice(&peers);
            raw.push(b'e');
            let head = format!("HTTP/1.0 200 OK\r\nContent-Length: {}\r\n\r\n", raw.len());
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf).await;
            if sock.write_all(head.as_bytes()).await.is_err() {
                break;
            }
            if sock.write_all(&raw).await.is_err() {
                break;
            }
        }
    });
    addr
}

/// Mini-seeder: sends the full bitfield right after the handshake;
/// interested -> unchoke; request -> piece (the engine_loop.rs
/// closed-loop shape + the bitfield face).
async fn mini_seeder(content: Vec<u8>) -> std::net::SocketAddr {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
    let addr = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
    tokio::spawn(async move {
        let Ok((mut sock, _)) = listener.accept().await else {
            return;
        };
        let mut hs = [0u8; 68];
        if sock.read_exact(&mut hs).await.is_err() {
            return;
        }
        let mut resp = [0u8; 68];
        resp[0] = 19;
        resp[1..20].copy_from_slice(b"BitTorrent protocol");
        resp[25] = 0x10; // extended
        resp[27] = 0x04; // fast
        resp[28..48].copy_from_slice(&hs[28..48]); // echo the info_hash
        resp[48..68].copy_from_slice(b"SEEDERSEEDERSEEDER00");
        let _ = sock.write_all(&resp).await;
        // Full bitfield (2 pieces -> 0xC0): the peer-bitfield data
        // source for the getPeers seeder face and tellStatus numSeeders
        // (AvailEvent::Bitfield). The length prefix = id + payload = 2.
        let _ = sock.write_all(&[0, 0, 0, 2, 5, 0xC0]).await;
        loop {
            let mut len_buf = [0u8; 4];
            if sock.read_exact(&mut len_buf).await.is_err() {
                break;
            }
            let len = u32::from_be_bytes(len_buf) as usize;
            if len == 0 {
                continue;
            }
            let mut body = vec![0u8; len];
            if sock.read_exact(&mut body).await.is_err() {
                break;
            }
            match body[0] {
                2 => {
                    // interested -> unchoke.
                    let _ = sock.write_all(&[0, 0, 0, 1, 1]).await;
                }
                6 => {
                    let index = u32::from_be_bytes([body[1], body[2], body[3], body[4]]);
                    let begin = u32::from_be_bytes([body[5], body[6], body[7], body[8]]);
                    let length = u32::from_be_bytes([body[9], body[10], body[11], body[12]]);
                    let off = index as usize * SEED_PIECE_LEN as usize + begin as usize;
                    let block = content[off..off + length as usize].to_vec();
                    let mut frame = Vec::new();
                    frame.extend_from_slice(((9 + block.len()) as u32).to_be_bytes().as_slice());
                    frame.push(7u8);
                    frame.extend_from_slice(&index.to_be_bytes());
                    frame.extend_from_slice(&begin.to_be_bytes());
                    frame.extend_from_slice(&block);
                    let _ = sock.write_all(&frame).await;
                }
                _ => {}
            }
        }
    });
    addr
}

/// addTorrent -> the engine closes the download loop from the local
/// mini-seeder -> tellStatus field snapshot (including the synthesized
/// bitfield) -> getPeers snapshot with all fields present
/// (transport=TCP, the measured path) -> the GID prefix resolves to
/// the same answer.
#[tokio::test]
async fn tell_status_snapshot_on_local_seeder_closed_loop() {
    let content = seed_content();
    let seeder_addr = mini_seeder(content.clone()).await;
    let tracker = loopback_tracker(seeder_addr).await;
    let (handle, join) = SessionActor::spawn();
    let dir = temp_dir("snapshot");
    let bytes =
        downloadable_v1_torrent(&content, &format!("http://{tracker}/announce"), "blob.bin");
    let gid = gid_of(&call(&handle, torrent_cmd(bytes, &dir)).await);

    // Download loop: poll until the synthesized bitmap is all ones
    // (2 pieces -> 0xC0) and completed = total.
    let mut snap: Option<TorrentStatusView> = None;
    for _ in 0..300 {
        match call(
            &handle,
            SessionCommand::TellStatus {
                gid: gid.to_string(),
                keys: vec![],
            },
        )
        .await
        {
            Ok(CommandReply::TorrentStatus(v)) => {
                // Active|Seeding: the break predicate races the
                // SeedingStarted transfer (see the boundary note
                // below) — the resident's flipped 'seeding' projection
                // (the finalized projection) is a valid terminal sample.
                if matches!(v.status, StatusKind::Active | StatusKind::Seeding)
                    && v.completed_length == v.total_length
                    && v.total_length == content.len() as u64
                {
                    snap = Some(*v);
                    break;
                }
            }
            other => panic!("tellStatus must succeed, got {other:?}"),
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let v = snap.unwrap_or_else(|| panic!("download never completed"));
    // ---- gatherProgressCommon field face (RpcMethodImpl.cc) ----
    assert_eq!(v.gid, gid);
    // The sample sits at the download → seed transfer boundary (the
    // bitmap all-ones break races the SeedingStarted consume): before
    // it the task is an active download, after it a seeding resident —
    // whose tellStatus status is 'seeding' since the unified
    // projection finalization (the interim 'active'
    // is closed). Both faces are the correct live projections.
    assert!(
        matches!(v.status, StatusKind::Active | StatusKind::Seeding),
        "transfer-boundary status drifted: {:?}",
        v.status
    );
    assert_eq!(v.total_length, 2 * SEED_PIECE_LEN);
    assert_eq!(v.completed_length, 2 * SEED_PIECE_LEN);
    assert!(v.connections >= 1, "seeder connection must be live");
    // Synthesized bitfield: v1 = the real bitmap (same convention);
    // 2 pieces all ones -> 0xC0.
    let bf = v.bitfield.clone().unwrap_or_else(|| panic!("bitfield"));
    assert_eq!(bf, vec![0xC0u8], "synthesized bitfield must be all-on");
    assert_eq!(v.piece_length, SEED_PIECE_LEN as u32);
    assert_eq!(v.num_pieces, 2);
    assert_eq!(v.seeder, Some(true), "all faces complete → seeder");
    // Per-file completed lengths (folded from bitmap ranges).
    assert_eq!(v.files.len(), 1);
    assert_eq!(v.files[0].path, "blob.bin");
    assert_eq!(v.files[0].completed_length, content.len() as u64);
    assert_eq!(v.files[0].piece_size, SEED_PIECE_LEN as u32);
    // ---- bittorrent sub-dict (gatherBitTorrentMetadata + SPEC
    // additions) ----
    let bt = v.bittorrent.clone().unwrap_or_else(|| panic!("bittorrent"));
    assert_eq!(bt.mode, Some("single"));
    assert_eq!(bt.meta_version, Some(1));
    assert_eq!(bt.private, Some(false));
    assert_eq!(bt.comment.as_deref(), Some("p35 snapshot"));
    assert_eq!(bt.creation_date, Some(1700000000));
    assert_eq!(bt.name.as_deref(), Some("blob.bin"));
    assert_eq!(bt.announce_list.len(), 1);
    assert!(bt.v2_info_hash.is_none(), "v1-only torrent has no v2 hash");
    // numSeeders = the count of peers with a full bitfield (the
    // mini-seeder sent a full bitfield).
    assert_eq!(v.num_seeders, 1, "seeder peer with full bitfield");

    // ---- getPeers (gatherPeer field face, RpcMethodImpl.cc) ----
    let mut peers_found = false;
    for _ in 0..50 {
        match call(
            &handle,
            SessionCommand::GetPeers {
                gid: gid.to_string(),
            },
        )
        .await
        {
            Ok(CommandReply::Peers(peers)) => {
                if let Some(p) = peers.first() {
                    // All fields present.
                    let PeerEntryView {
                        peer_id,
                        ip,
                        port,
                        bitfield,
                        am_choking,
                        peer_choking,
                        download_speed: _,
                        upload_speed: _,
                        seeder,
                        transport,
                        crypto,
                    } = p;
                    const SEEDER_PEER_ID: [u8; 20] = *b"SEEDERSEEDERSEEDER00";
                    assert_eq!(
                        peer_id.as_ref(),
                        Some(&SEEDER_PEER_ID),
                        "handshake peer id captured at registration"
                    );
                    assert_eq!(ip, "127.0.0.1");
                    assert_eq!(*port, seeder_addr.port(), "outbound → real port");
                    assert_eq!(bitfield, &vec![0xC0u8], "peer bitfield from AvailEvent");
                    assert!(*seeder, "full peer bitfield → seeder");
                    assert_eq!(*transport, PeerTransportKind::Tcp, "unmerged is always TCP");
                    assert_eq!(*crypto, PeerCryptoKind::Plain, "legacy direct connection");
                    // Value-range narrowing: peer_choking is always
                    // false (module note).
                    assert!(!*peer_choking);
                    // am_choking: true until the seeding round selects
                    // us (the BEP3 initial state).
                    let _ = am_choking;
                    peers_found = true;
                    break;
                }
            }
            other => panic!("getPeers must succeed, got {other:?}"),
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(peers_found, "seeder peer must appear in getPeers");

    // ---- GID prefix resolution (integration face): a 13-char prefix
    // answers the same ----
    match call(
        &handle,
        SessionCommand::TellStatus {
            gid: gid.to_string()[..13].to_string(),
            keys: vec![],
        },
    )
    .await
    {
        Ok(CommandReply::TorrentStatus(v2)) => assert_eq!(v2.gid, gid),
        other => panic!("prefix resolve must work, got {other:?}"),
    }

    // getServers: an active task = the tracker table snapshot (the fake
    // tracker row has been successfully attributed).
    match call(
        &handle,
        SessionCommand::GetServers {
            gid: gid.to_string(),
        },
    )
    .await
    {
        Ok(CommandReply::Servers(servers)) => {
            assert_eq!(servers.len(), 1, "single tier");
            assert_eq!(servers[0].tier, 0);
            assert_eq!(servers[0].status, "working", "announce succeeded");
        }
        other => panic!("getServers must succeed, got {other:?}"),
    }
    // getUris: a direct .torrent add task = an empty URI table (BEP19
    // webseeding).
    match call(
        &handle,
        SessionCommand::GetUris {
            gid: gid.to_string(),
        },
    )
    .await
    {
        Ok(CommandReply::Uris(uris)) => assert!(uris.is_empty()),
        other => panic!("getUris must succeed, got {other:?}"),
    }

    // Teardown: remove -> terminal entry (tellStopped field snapshot:
    // errorCode 31).
    assert_eq!(
        call(
            &handle,
            SessionCommand::Remove {
                gid: gid.to_string()
            }
        )
        .await,
        Ok(CommandReply::Gid(gid))
    );
    let mut stopped = Vec::new();
    for _ in 0..100 {
        stopped = status_list(
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
        if !stopped.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(stopped.len(), 1);
    assert_eq!(stopped[0].status, StatusKind::Removed);
    assert_eq!(
        stopped[0].error_code,
        Some(31),
        "REMOVED = 31（error_code.h）"
    );

    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// bittorrent dict field snapshot (v2-only shape; the dict half of the
/// closed-loop check): metaVersion=2, v2InfoHash 64-hex, infoHash =
/// truncated v2 (field convention), files[].piecesRoot hex +
/// pieceSize + padding.
#[tokio::test]
async fn tell_status_bittorrent_dict_v2_snapshot() {
    let global = GlobalOptions {
        max_concurrent_downloads: 1,
        ..Default::default()
    };
    let (handle, join) = SessionActor::spawn_with(SessionOptions { global });
    let dir = temp_dir("btdict");
    // A occupies the active slot (dead tracker); B = the v2-only task
    // under query (waiting).
    let bytes_a = build_v2_torrent(&vec![1u8; 128 * 1024], &dead_tracker());
    let _a = gid_of(&call(&handle, torrent_cmd(bytes_a, &dir)).await);
    let bytes_b = build_v2_torrent_named(&vec![2u8; 128 * 1024], &dead_tracker(), "v2-b.bin");
    let b = gid_of(&call(&handle, torrent_cmd(bytes_b, &dir)).await);

    match call(
        &handle,
        SessionCommand::TellStatus {
            gid: b.to_string(),
            keys: vec![],
        },
    )
    .await
    {
        Ok(CommandReply::TorrentStatus(v)) => {
            assert_eq!(v.status, StatusKind::Waiting);
            let bt = v.bittorrent.clone().unwrap_or_else(|| panic!("bt"));
            assert_eq!(bt.meta_version, Some(2), "v2-only → meta version 2");
            let v2 = bt.v2_info_hash.unwrap_or_else(|| panic!("v2 hash"));
            assert_eq!(v2.len(), 32);
            // infoHash = the v1 sha1 20-byte hex; v2-only is always
            // truncated.
            let ih = v.info_hash.unwrap_or_else(|| panic!("info hash"));
            assert_eq!(&ih, &v2[..20], "truncated sha256 semantics");
            // metainfo parsed -> the private face is knowable (key
            // absent = false, the metainfo.rs BEP27 parsing
            // convention).
            assert_eq!(bt.private, Some(false));
            // No bitmap on the waiting face (same rule as aria2 having
            // no piece storage).
            assert!(v.bitfield.is_none());
            assert_eq!(v.seeder, Some(false));
            // files: v2 files carry piecesRoot (converted to hex at the
            // RPC layer).
            assert_eq!(v.files.len(), 1);
            assert!(v.files[0].pieces_root.is_some(), "v2 non-empty file root");
            assert_eq!(v.files[0].piece_size, 64 * 1024);
            assert!(!v.files[0].padding);
        }
        other => panic!("tellStatus must succeed, got {other:?}"),
    }
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// Full-tier .torrent intake (BEP12 "The `announce-list` key
/// is a list of tiers of announces") — a torrent with
/// announce-list=[[u1,u2],[u3]] ingested via addTorrent -> the task's
/// tracker table = two tiers (order kept within a tier), not the
/// single tier of just the first URL. Observation face = tellStatus
/// bittorrent.announceList (torrent_bittorrent_view's direct
/// projection of TorrentJob.tiers).
#[tokio::test]
async fn add_torrent_ingests_full_announce_tiers() {
    let (handle, join) = SessionActor::spawn();
    let dir = temp_dir("pc01-tiers");
    // Unreachable trackers (127.0.0.1:1/2 -> immediate connection
    // refusal): the intake assertions do not depend on network
    // round-trips.
    let bytes = build_v2_torrent_multi_tier(
        &vec![7u8; 128 * 1024],
        &[
            &["http://127.0.0.1:1/announce", "http://127.0.0.1:1/alt"],
            &["http://127.0.0.1:2/announce"],
        ],
    );
    let gid = gid_of(&call(&handle, torrent_cmd(bytes, &dir)).await);
    match call(
        &handle,
        SessionCommand::TellStatus {
            gid: gid.to_string(),
            keys: vec![],
        },
    )
    .await
    {
        Ok(CommandReply::TorrentStatus(v)) => {
            let bt = v.bittorrent.clone().unwrap_or_else(|| panic!("bt"));
            assert_eq!(
                bt.announce_list,
                vec![
                    vec![
                        "http://127.0.0.1:1/announce".to_string(),
                        "http://127.0.0.1:1/alt".to_string()
                    ],
                    vec!["http://127.0.0.1:2/announce".to_string()],
                ],
                "BEP12 full tier ingestion: two tiers, order preserved within a tier"
            );
        }
        other => panic!("tellStatus must succeed, got {other:?}"),
    }
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// Terminal-entry file_views budget: after removing a 300-file task,
/// tellStopped's files truncate to MAX_RESULT_FILES (256), the last
/// entry carries the `[+N more truncated]` note, and num_files_full =
/// 300.
#[tokio::test]
async fn result_entry_files_budget_truncates() {
    use bencode::Value;
    use sha1::{Digest as _, Sha1};
    const P: usize = 16384;
    let n_files = crate::session::actor::views::MAX_RESULT_FILES + 50;
    // 300-file v1 seed: 1 byte per file; a single-piece stream hash
    // covers all (piece length 16KiB > total -> one piece).
    let total: Vec<u8> = vec![0x41u8; n_files];
    let mut files = Vec::new();
    for i in 0..n_files {
        files.push(Value::Dict(
            vec![
                (b"length".to_vec(), Value::Int(1)),
                (
                    b"path".to_vec(),
                    Value::List(vec![Value::Bytes(format!("f{i:03}.bin").into_bytes())]),
                ),
            ]
            .into_iter()
            .collect(),
        ));
    }
    let info = Value::Dict(
        vec![
            (b"files".to_vec(), Value::List(files)),
            (b"name".to_vec(), Value::Bytes(b"budget".to_vec())),
            (b"piece length".to_vec(), Value::Int(P as i64)),
            (
                b"pieces".to_vec(),
                Value::Bytes(Sha1::digest(&total).to_vec()),
            ),
        ]
        .into_iter()
        .collect(),
    );
    let torrent = Value::Dict(
        vec![
            (
                b"announce".to_vec(),
                Value::Bytes(dead_tracker().into_bytes()),
            ),
            (b"info".to_vec(), info),
        ]
        .into_iter()
        .collect(),
    );
    let torrent = taiji_bt::bencode::encode(&torrent).unwrap_or_else(|e| panic!("encode: {e}"));
    let dir = temp_dir("sec13-budget");
    let (handle, join) = SessionActor::spawn_with(SessionOptions {
        global: GlobalOptions {
            dir: dir.clone(),
            ..Default::default()
        },
    });
    let gid = gid_of(&call(&handle, torrent_cmd(torrent, &dir)).await);
    // remove -> terminal entry.
    assert_eq!(
        call(
            &handle,
            SessionCommand::Remove {
                gid: gid.to_string()
            }
        )
        .await,
        Ok(CommandReply::Gid(gid))
    );
    let mut stopped = Vec::new();
    for _ in 0..100 {
        stopped = status_list(
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
        if !stopped.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(stopped.len(), 1, "the terminal entry is in place");
    let e = &stopped[0].files;
    assert_eq!(
        e.len(),
        crate::session::actor::views::MAX_RESULT_FILES,
        "files truncated to the budget cap"
    );
    assert_eq!(stopped[0].num_files_full, Some(n_files as u64));
    assert!(
        e.last()
            .is_some_and(|f| f.path.ends_with("more truncated]")),
        "the last entry carries the truncation note"
    );
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    let _ = std::fs::remove_dir_all(&dir);
}

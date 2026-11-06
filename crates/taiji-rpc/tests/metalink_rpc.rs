//! addMetalink method-face e2e (feature `metalink` enabled): the
//! on-state half, metaurl direct BT conversion, and the multi-file GID
//! chain. Real sockets + a real SessionActor; the `.torrent` metadata
//! source is an in-process axum mock.
//!
//! The HTTP client is a raw HTTP/1.1 client over a native tokio
//! TcpStream (harness isomorphic to rpc_methods_http.rs).
//!
//! This suite compiles only in the on state (the method does not exist
//! when off; the two-state registration assertions live in
//! feature_gate.rs — under `--no-default-features` the whole tree
//! compiles empty).
#![cfg(feature = "metalink")]

use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

use taiji_core::session::SessionActor;
use taiji_rpc::{RpcConfig, serve};

async fn spawn_with_secret(secret: &str) -> (taiji_rpc::ServerHandle, CancellationToken) {
    let (session, _join) = SessionActor::spawn();
    let config = RpcConfig {
        port: 0,
        secret: Some(secret.to_string()),
        allow_origin_all: false,
        max_request_size: 10 * 1024 * 1024,
        ..Default::default()
    };
    let token = CancellationToken::new();
    let handle = serve(config, std::sync::Arc::new(session), token.clone())
        .await
        .unwrap_or_else(|e| panic!("serve failed: {e}"));
    (handle, token)
}

async fn rpc(addr: std::net::SocketAddr, secret: &str, method: &str, params: Value) -> Value {
    let mut arr = vec![json!(format!("token:{secret}"))];
    if let Value::Array(rest) = params {
        arr.extend(rest);
    }
    let body = json!({"jsonrpc": "2.0", "id": "t", "method": method, "params": arr});
    let payload = body.to_string();
    let mut s = TcpStream::connect(addr)
        .await
        .unwrap_or_else(|e| panic!("connect {addr}: {e}"));
    let req = format!(
        "POST /jsonrpc HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{}",
        payload.len(),
        payload
    );
    s.write_all(req.as_bytes())
        .await
        .unwrap_or_else(|e| panic!("write: {e}"));
    let mut buf = Vec::new();
    match tokio::time::timeout(Duration::from_secs(10), s.read_to_end(&mut buf)).await {
        Ok(Ok(_)) => {}
        other => panic!("read_to_end: {other:?}"),
    }
    let text = String::from_utf8_lossy(&buf).to_string();
    let payload = text.split("\r\n\r\n").nth(1).unwrap_or_default();
    serde_json::from_str(payload).unwrap_or_else(|e| panic!("json parse {e}: {text:?}"))
}

// ---- test material ----

/// Minimal v1 torrent (single file; announce points at an unreachable
/// port — after the upgrade the task only attempts the BT side, which
/// does not affect the bittorrent sub-dict presentation).
fn minimal_torrent_bytes() -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(b"d8:announce27:http://127.0.0.1:1/announce4:infod");
    b.extend_from_slice(b"6:lengthi64e4:name7:m4g.iso");
    b.extend_from_slice(b"12:piece lengthi16384e6:pieces20:");
    let mut pieces = [0u8; 20];
    for (i, slot) in pieces.iter_mut().enumerate() {
        *slot = i as u8;
    }
    b.extend_from_slice(&pieces);
    b.extend_from_slice(b"ee");
    b
}

/// Standard base64 encoding (RFC 4648 §4 with padding; self-contained
/// test surface, zero new dependencies).
fn b64(data: &[u8]) -> String {
    const ALPHA: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(ALPHA[(n >> 18) as usize & 63] as char);
        out.push(ALPHA[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            ALPHA[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHA[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// GID shape assertion (aria2 reply face: hex16; top bit set).
fn assert_gid_shape(v: &Value, ctx: &str) {
    let s = v
        .as_str()
        .unwrap_or_else(|| panic!("{ctx}: gid must be a string: {v}"));
    assert_eq!(s.len(), 16, "{ctx}: hex16, got {s}");
    let n = u64::from_str_radix(s, 16).unwrap_or_else(|e| panic!("{ctx}: {s}: {e}"));
    assert!(
        n & 0x8000_0000_0000_0000 != 0,
        "{ctx}: gid top bit set: {s}"
    );
}

// ---- on-state half + multi-file GID chain: pure GID array ----

const MULTI_FILE_DOC: &str = r#"<metalink xmlns="urn:ietf:params:xml:ns:metalink">
  <file name="a.iso"><size>3</size>
    <url priority="1">http://a.test/a.iso</url>
    <url priority="2">ftp://b.test/a.iso</url>
    <hash type="sha-256">aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa</hash>
  </file>
  <file name="b.iso"><size>4</size>
    <url priority="1">https://c.test/b.iso</url>
  </file>
  <file name="c.iso"><size>5</size>
    <url priority="1">rsync://skip.me/c.iso</url>
  </file>
</metalink>"#;

/// addMetalink on-state e2e: a multi-file document -> a **pure GID
/// string array** (aria2 shape); the GID chain = one task GID per
/// document entry in order (c.iso's only rsync mirror is dropped by the
/// mirror-family filter -> no GID); `--out` follows the entry name
/// (getUris sees the mirror set, multiple sources under one GID).
#[tokio::test]
async fn add_metalink_open_state_returns_pure_gid_array_in_document_order() {
    let (handle, token) = spawn_with_secret("m").await;
    let addr = handle.local_addr;
    let doc_b64 = b64(MULTI_FILE_DOC.as_bytes());
    let r = rpc(
        addr,
        "m",
        "taiji.addMetalink",
        json!([doc_b64, {"dir": "/tmp/tj-ml-e2e"}]),
    )
    .await;
    let gids = r["result"]
        .as_array()
        .unwrap_or_else(|| panic!("result must be a pure GID array: {r}"));
    assert_eq!(gids.len(), 2, "two usable entries → two GIDs: {r}");
    for g in gids {
        assert_gid_shape(g, "gid shape");
    }
    // GID chain: each GID independently queryable (aria2 per-GID
    // tellStatus semantics).
    for g in gids {
        let gid = g.as_str().unwrap_or_default().to_string();
        let status = rpc(addr, "m", "taiji.tellStatus", json!([gid.clone()])).await;
        assert_eq!(
            status["result"]["gid"],
            json!(gid),
            "per-gid tellStatus roundtrip: {status}"
        );
    }
    // Multi-source mirrors (a.iso's two URLs) hang off the first GID
    // (getUris sees the full set).
    let first = gids[0].as_str().unwrap_or_default().to_string();
    let uris = rpc(addr, "m", "taiji.getUris", json!([first])).await;
    let uri_list: Vec<&str> = uris["result"]
        .as_array()
        .map(|a| a.iter().filter_map(|u| u["uri"].as_str()).collect())
        .unwrap_or_default();
    assert!(
        uri_list.contains(&"http://a.test/a.iso") && uri_list.contains(&"ftp://b.test/a.iso"),
        "mirrors expand under one GID: {uri_list:?}"
    );
    token.cancel();
    if let Err(e) = handle.join().await {
        panic!("server join: {e:?}");
    }
}

// ---- metaurl direct BT conversion e2e ----

/// magnet metaurl: converts into the existing magnet entry (a BT task;
/// the bittorrent sub-dict is immediately visible); the same entry's
/// HTTP mirror gets an independent GID (failure-isolation surface).
#[tokio::test]
async fn magnet_metaurl_converts_to_bittorrent_task() {
    let (handle, token) = spawn_with_secret("m").await;
    let addr = handle.local_addr;
    let doc = r#"<metalink xmlns="urn:ietf:params:xml:ns:metalink">
      <file name="x.iso"><size>3</size>
        <url>http://dead.test/x.iso</url>
        <metaurl mediatype="torrent">magnet:?xt=urn:btih:1111111111111111111111111111111111111111&amp;dn=x</metaurl>
      </file>
    </metalink>"#;
    let r = rpc(
        addr,
        "m",
        "addMetalink",
        json!([b64(doc.as_bytes()), {"dir": "/tmp/tj-ml-e2e"}]),
    )
    .await;
    let gids = r["result"]
        .as_array()
        .unwrap_or_else(|| panic!("pure GID array: {r}"));
    assert_eq!(gids.len(), 2, "BT(x) + http(x): {r}");
    assert_gid_shape(&gids[0], "bt gid");
    assert_gid_shape(&gids[1], "http gid");
    // BT typing: GID[0] = the magnet task (bittorrent sub-dict).
    let bt = rpc(
        addr,
        "m",
        "taiji.tellStatus",
        json!([gids[0].as_str().unwrap_or_default()]),
    )
    .await;
    assert!(
        bt["result"]
            .get("bittorrent")
            .is_some_and(|v| v.is_object()),
        "metaurl GID must carry the bittorrent dict: {bt}"
    );
    // HTTP typing: GID[1] has no bittorrent sub-dict (independent GID,
    // independent state — a metaurl failure must not affect the same
    // <file> HTTP-source task: the isolation premise).
    let http = rpc(
        addr,
        "m",
        "taiji.tellStatus",
        json!([gids[1].as_str().unwrap_or_default()]),
    )
    .await;
    assert!(
        http["result"].get("bittorrent").is_none(),
        "http face GID must not carry bittorrent dict: {http}"
    );
    token.cancel();
    if let Err(e) = handle.join().await {
        panic!("server join: {e:?}");
    }
}

/// `.torrent` URL metaurl: converts into the existing torrent-metadata
/// entry — after the mock is fetched, the **same GID upgrades in place**
/// to a torrent task (direct-conversion semantics inside the engine);
/// the bittorrent sub-dict appears with the upgrade.
#[tokio::test]
async fn torrent_url_metaurl_upgrades_to_bittorrent_task_in_place() {
    // In-process mock: the only .torrent metadata source.
    let torrent = minimal_torrent_bytes();
    let app = axum::Router::new().route(
        "/dist/m4g.torrent",
        axum::routing::get(move || {
            let body = torrent.clone();
            async move {
                (
                    [(axum::http::header::CONTENT_TYPE, "application/x-bittorrent")],
                    body,
                )
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("mock bind: {e}"));
    let mock_addr = listener
        .local_addr()
        .unwrap_or_else(|e| panic!("addr: {e}"));
    let mock = tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .unwrap_or_else(|e| panic!("mock serve: {e}"));
    });

    let (handle, token) = spawn_with_secret("m").await;
    let addr = handle.local_addr;
    let doc = format!(
        r#"<metalink xmlns="urn:ietf:params:xml:ns:metalink">
          <file name="m4g.iso"><size>64</size>
            <metaurl mediatype="torrent">http://{mock_addr}/dist/m4g.torrent</metaurl>
          </file>
        </metalink>"#
    );
    let r = rpc(
        addr,
        "m",
        "taiji.addMetalink",
        json!([b64(doc.as_bytes()), {"dir": "/tmp/tj-ml-e2e"}]),
    )
    .await;
    let gids = r["result"]
        .as_array()
        .unwrap_or_else(|| panic!("pure GID array: {r}"));
    assert_eq!(gids.len(), 1, "metaurl-only entry → one BT GID: {r}");
    let gid = gids[0].as_str().unwrap_or_default().to_string();
    assert_gid_shape(&gids[0], "metaurl gid");

    // Poll until the metadata fetch completes + the in-place upgrade
    // (same GID; bittorrent sub-dict present).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let mut upgraded = None;
    while tokio::time::Instant::now() < deadline {
        let status = rpc(addr, "m", "taiji.tellStatus", json!([gid.clone()])).await;
        if status["result"]
            .get("bittorrent")
            .is_some_and(|v| v.is_object())
        {
            upgraded = Some(status);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let status = upgraded.unwrap_or_else(|| panic!("metaurl task must upgrade to BT in place"));
    assert_eq!(
        status["result"]["gid"],
        json!(gid),
        "same GID in-place upgrade"
    );
    // The torrent name comes from the metadata (info name), not the
    // entry name — corroborating the direct-conversion semantics.
    assert_eq!(
        status["result"]["bittorrent"]["info"]["name"],
        json!("m4g.iso"),
        "bittorrent info carries the metadata name: {status}"
    );
    token.cancel();
    mock.abort();
    if let Err(e) = handle.join().await {
        panic!("server join: {e:?}");
    }
}

/// Duplicate magnet identity e2e (same btih, different dn/tr spellings
/// across entries): the later BT candidate is skipped at the expansion
/// seam with a warning (first seen wins), and **every other entry is
/// still created** — a benign duplicate must not fail the whole method
/// and kill the document's later entries.
#[tokio::test]
async fn duplicate_magnet_metaurl_skips_bt_entry_but_keeps_other_tasks() {
    let (handle, token) = spawn_with_secret("m").await;
    let addr = handle.local_addr;
    let doc = r#"<metalink xmlns="urn:ietf:params:xml:ns:metalink">
      <file name="x.iso"><size>3</size>
        <url priority="1">http://a.test/x.iso</url>
        <metaurl mediatype="torrent">magnet:?xt=urn:btih:1111111111111111111111111111111111111111&amp;dn=x</metaurl>
      </file>
      <file name="y.iso"><size>3</size>
        <url priority="1">http://b.test/y.iso</url>
        <metaurl mediatype="torrent">magnet:?xt=urn:btih:1111111111111111111111111111111111111111&amp;dn=y-copy&amp;tr=http%3A%2F%2Ft.test%2Fann</metaurl>
      </file>
      <file name="z.iso"><size>3</size>
        <metaurl mediatype="torrent">magnet:?xt=urn:btih:2222222222222222222222222222222222222222&amp;dn=z</metaurl>
      </file>
    </metalink>"#;
    let r = rpc(
        addr,
        "m",
        "taiji.addMetalink",
        json!([b64(doc.as_bytes()), {"dir": "/tmp/tj-ml-e2e"}]),
    )
    .await;
    let gids = r["result"]
        .as_array()
        .unwrap_or_else(|| panic!("pure GID array: {r}"));
    assert_eq!(
        gids.len(),
        4,
        "BT(x) + http(x) + http(y) + BT(z); y's duplicate-magnet BT is absorbed at \
         the seam while every other task is created: {r}"
    );
    // Typing check: [0]=BT(x) and [3]=BT(z) carry the bittorrent dict;
    // [1]/[2] are pure HTTP faces (independent GID, independent state —
    // the skip only applies to BT candidates).
    for (idx, bt_expected) in [(0usize, true), (1, false), (2, false), (3, true)] {
        let gid = gids[idx].as_str().unwrap_or_default().to_string();
        assert_gid_shape(&gids[idx], "gid shape");
        let status = rpc(addr, "m", "taiji.tellStatus", json!([gid])).await;
        let has_bt = status["result"]
            .get("bittorrent")
            .is_some_and(|v| v.is_object());
        assert_eq!(
            has_bt, bt_expected,
            "gid[{idx}] bittorrent typing mismatch: {status}"
        );
    }
    token.cancel();
    if let Err(e) = handle.join().await {
        panic!("server join: {e:?}");
    }
}

/// Extended-domain check (RFC 5854 six hash families): an entry
/// declaring only a sha-512 `<hash>` -> the expanded HTTP task carries
/// `checksum=sha-512=<hex>` (the verdict rides the task) — proven by
/// the getOption echo. sha-512 lies outside the plain `--checksum`
/// value domain, so without this carry AddUri would reject at the
/// expansion seam and fail the whole method.
#[tokio::test]
async fn sha512_only_metalink_task_carries_checksum_verdict() {
    let (handle, token) = spawn_with_secret("m").await;
    let addr = handle.local_addr;
    // sha-512 digest length = 128 hex (a legal shape for the parse-side
    // length check).
    let digest = "b".repeat(128);
    let doc = format!(
        r#"<metalink xmlns="urn:ietf:params:xml:ns:metalink">
          <file name="s.iso"><size>3</size>
            <url priority="1">http://a.test/s.iso</url>
            <hash type="sha-512">{digest}</hash>
          </file>
        </metalink>"#
    );
    let r = rpc(
        addr,
        "m",
        "taiji.addMetalink",
        json!([b64(doc.as_bytes()), {"dir": "/tmp/tj-ml-e2e"}]),
    )
    .await;
    let gids = r["result"]
        .as_array()
        .unwrap_or_else(|| panic!("sha-512-only entry must expand into a task: {r}"));
    assert_eq!(gids.len(), 1, "one HTTP plan: {r}");
    let gid = gids[0].as_str().unwrap_or_default().to_string();
    // The task options echo checksum (the verdict persists with the
    // task).
    let opt = rpc(addr, "m", "taiji.getOption", json!([gid])).await;
    assert_eq!(
        opt["result"]["checksum"].as_str(),
        Some(format!("sha-512={digest}").as_str()),
        "sha-512 declaration must ride the task as its checksum verdict: {opt}"
    );
    token.cancel();
    if let Err(e) = handle.join().await {
        panic!("server join: {e:?}");
    }
}

// ---- error surface (difference-declaration material; string codes owned by the error table) ----

/// Expansion-surface (dir,out) collision e2e (negative regression):
/// basename flattening collides sub1/a.iso and sub2/a.iso (plus the
/// duplicate `<file name>`) onto the same out — later entries are
/// skipped at the expansion surface (double writes to the same part
/// file are sealed off) and the reply contains only the first entry's
/// GID.
#[tokio::test]
async fn flattened_basename_collision_yields_single_task() {
    let (handle, token) = spawn_with_secret("m").await;
    let addr = handle.local_addr;
    let doc = r#"<metalink xmlns="urn:ietf:params:xml:ns:metalink">
      <file name="sub1/a.iso"><size>3</size><url priority="1">http://a.test/a.iso</url></file>
      <file name="sub2/a.iso"><size>3</size><url priority="1">http://b.test/a.iso</url></file>
      <file name="a.iso"><size>3</size><url priority="1">http://c.test/a.iso</url></file>
    </metalink>"#;
    let r = rpc(
        addr,
        "m",
        "taiji.addMetalink",
        json!([b64(doc.as_bytes()), {"dir": "/tmp/tj-ml-e2e"}]),
    )
    .await;
    let gids = r["result"]
        .as_array()
        .unwrap_or_else(|| panic!("pure GID array: {r}"));
    assert_eq!(
        gids.len(),
        1,
        "three entries flatten to one (dir,out); only the first may occupy it: {r}"
    );
    token.cancel();
    if let Err(e) = handle.join().await {
        panic!("server join: {e:?}");
    }
}

/// Parse-surface error codes e2e: bad base64 / v3 explicit decline
/// (unsupported_version) / malformed v4 (parse_failed) + the legacy
/// option family absorbed with a warning (the method does not fail).
#[tokio::test]
async fn metalink_error_surface_and_option_family_absorption() {
    let (handle, token) = spawn_with_secret("m").await;
    let addr = handle.local_addr;
    // Bad base64 = explicit execution error (same semantics as aria2
    // DECODE_FAILURE).
    let r = rpc(addr, "m", "taiji.addMetalink", json!(["not/base64!"])).await;
    assert_eq!(
        r["error"]["message"],
        json!("metalink data is not valid base64."),
        "{r}"
    );
    // v3 = explicit decline (declined by default; a declared
    // difference).
    let v3 = r#"<metalink xmlns="http://www.metalinker.org/" version="3.0" type="dynamic">
      <files><file name="old.iso"><size>1</size><url>http://a.test/old.iso</url></file></files>
    </metalink>"#;
    let r = rpc(addr, "m", "taiji.addMetalink", json!([b64(v3.as_bytes())])).await;
    assert!(
        r["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .starts_with("taiji.metalink.unsupported_version:"),
        "v3 declines explicitly: {r}"
    );
    // Malformed v4 = parse_failed.
    let bad = r#"<metalink xmlns="urn:ietf:params:xml:ns:metalink"><not-a-file/></metalink>"#;
    let r = rpc(addr, "m", "taiji.addMetalink", json!([b64(bad.as_bytes())])).await;
    assert!(
        r["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .starts_with("taiji.metalink.parse_failed:"),
        "malformed v4 declines explicitly: {r}"
    );
    // Legacy option family = ignored with a warning (no failure); a
    // non-boolean auto-discover = value-domain rejection.
    let doc = r#"<metalink xmlns="urn:ietf:params:xml:ns:metalink">
      <file name="ok.iso"><size>1</size><url>http://a.test/ok.iso</url></file>
    </metalink>"#;
    let r = rpc(
        addr,
        "m",
        "taiji.addMetalink",
        json!([
            b64(doc.as_bytes()),
            {"dir": "/tmp/tj-ml-e2e", "metalink-language": "ja,en", "metalink-location": "JP"}
        ]),
    )
    .await;
    assert!(
        r["result"].is_array(),
        "legacy option family is ignored: {r}"
    );
    let r = rpc(
        addr,
        "m",
        "taiji.addMetalink",
        json!([b64(doc.as_bytes()), {"metalink-enable-auto-discover": "yes"}]),
    )
    .await;
    assert!(
        r["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .starts_with("taiji.option.invalid:"),
        "non-bool auto-discover = value-domain refusal: {r}"
    );
    // Zero usable tasks = an empty array (same shape as aria2
    // result.empty(), not an error).
    let doc = r#"<metalink xmlns="urn:ietf:params:xml:ns:metalink">
      <file name="d.iso"><size>1</size><url>rsync://d.test/d.iso</url></file>
    </metalink>"#;
    let r = rpc(addr, "m", "taiji.addMetalink", json!([b64(doc.as_bytes())])).await;
    assert_eq!(r["result"], json!([]), "no usable entry = empty array: {r}");
    token.cancel();
    if let Err(e) = handle.join().await {
        panic!("server join: {e:?}");
    }
}

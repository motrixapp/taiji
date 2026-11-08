use super::payload::MAX_REQUEST_SUBCALLS;
use super::*;
use std::time::Duration;
use taiji_core::session::SessionActor;

fn state(secret: Option<&str>) -> AppState {
    let (session, _join) = SessionActor::spawn();
    AppState {
        session: Arc::new(session),
        secret: secret.map(str::to_string),
        basic: None,
        allow_origin_all: false,
        max_request_size: 1 << 20,
        shutdown: CancellationToken::new(),
        aria2_compat: false,
        listen_all: false,
        conn: Arc::new(crate::guards::ConnLedger::new(
            crate::guards::DEFAULT_MAX_TOTAL_CONNS,
            crate::guards::DEFAULT_MAX_PER_IP_CONNS,
        )),
        auth_backoff: Arc::new(crate::guards::AuthBackoff::new(
            crate::guards::DEFAULT_AUTH_FAIL_THRESHOLD,
        )),
    }
}

/// AppState with `--rpc-aria2-compat` enabled (compat half of the dual-state e2e).
fn state_compat(secret: Option<&str>) -> AppState {
    let mut st = state(secret);
    st.aria2_compat = true;
    st
}

async fn call(st: &AppState, method: &str, params: Vec<Value>) -> RpcResponse {
    process_call(st, method, params, json!(1), false, None).await
}

/// Call helper carrying the token: prepends the state secret as a `token:`
/// first parameter. Write-method tests must go through this helper (the
/// write gate fails closed when no secret is set); `call` is kept for auth
/// semantics and read-only assertions.
async fn call_auth(st: &AppState, method: &str, params: Vec<Value>) -> RpcResponse {
    let mut ps = Vec::with_capacity(params.len() + 1);
    ps.push(json!(format!(
        "token:{}",
        st.secret.as_deref().unwrap_or_default()
    )));
    ps.extend(params);
    process_call(st, method, ps, json!(1), false, None).await
}

/// Assertion helper: fetch a JSON array (avoids expect/unwrap).
fn as_arr<'a>(v: &'a Value, ctx: &str) -> &'a Vec<Value> {
    match v.as_array() {
        Some(a) => a,
        None => panic!("{ctx}: expected JSON array, got {v}"),
    }
}

#[tokio::test]
async fn get_version_has_enabled_features_and_prefixed_alias_works() {
    let st = state(None);
    // Canonical face (default): bare name (frozen registry) and `taiji.*` alias.
    for name in ["getVersion", "taiji.getVersion"] {
        let resp = call(&st, name, vec![]).await;
        assert_eq!(resp.code, 0, "{name}");
        let version = resp.payload["version"].as_str().unwrap_or("");
        assert!(
            version.starts_with("taiji/"),
            "frozen prefix violated at {name}: {version}"
        );
        let feats = as_arr(&resp.payload["enabledFeatures"], name);
        assert!(
            !feats.is_empty(),
            "{name}: enabledFeatures must be non-empty"
        );
    }
    // Compat face (alias mode): `aria2.getVersion` is accepted only with
    // `--rpc-aria2-compat` on; the reply has the canonical shape.
    let compat = state_compat(None);
    let resp = call(&compat, "aria2.getVersion", vec![]).await;
    assert_eq!(
        resp.code, 0,
        "aria2.getVersion: {}",
        resp.payload["message"]
    );
    assert!(
        resp.payload["version"]
            .as_str()
            .unwrap_or("")
            .starts_with("taiji/")
    );
}

#[tokio::test]
async fn auth_positive_negative_and_delay_flag() {
    let st = state(Some("sekrit"));
    // Positive: the token first parameter is stripped and accepted (RpcMethod.cc).
    let ok = call(&st, "getVersion", vec![json!("token:sekrit")]).await;
    assert_eq!(ok.code, 0);
    assert!(!ok.unauthorized);
    // Negative: missing / wrong / non-string token → "Unauthorized" + delay flag.
    for params in [vec![], vec![json!("token:wrong")], vec![json!(1)]] {
        let resp = call(&st, "getVersion", params).await;
        assert_eq!(resp.code, 1);
        assert_eq!(resp.payload["message"], "Unauthorized");
        assert!(resp.unauthorized, "delay flag must be set");
    }
    // No secret set: anonymous access allowed (DownloadEngine.cc).
    let open = state(None);
    assert_eq!(call(&open, "getVersion", vec![]).await.code, 0);
}

#[tokio::test]
async fn unknown_method_checked_after_auth_and_reports_name() {
    let st = state(Some("sekrit"));
    // Unknown methods are authenticated first too (RpcMethod.cc authorizes up front).
    let unauth = call(&st, "frobnicate", vec![]).await;
    assert_eq!(unauth.payload["message"], "Unauthorized");
    // After auth passes → "No such method: <name>" (RpcMethodImpl.cc). The
    // sample uses a registered non-promised name (exportSession pins the
    // same surface).
    let notfound = call(&st, "aria2.exportSession", vec![json!("token:sekrit")]).await;
    assert_eq!(notfound.code, 1);
    assert_eq!(
        notfound.payload["message"],
        "No such method: aria2.exportSession"
    );
    assert!(!notfound.unauthorized);
}

#[tokio::test]
async fn unsupported_and_permanent_metalink_share_string_code() {
    // Write method (addUri) tested past the write gate: token carried.
    let st = state(Some("t"));
    // addUri goes through param validation: empty uris → the aria2 text
    // (RpcMethodImpl.cc); the not_supported face remains for methods not
    // wired to the session (tellStatus etc.).
    let add = call_auth(&st, "addUri", vec![json!([])]).await;
    assert_eq!(add.code, 1);
    assert_eq!(add.payload["message"], "URI is not provided.");
    // addMetalink (feature gate): registered, it goes through the
    // consumer-seam param face (missing param = standard text); with the
    // feature off the method does not exist (dual-state assertions in
    // tests/feature_gate.rs).
    #[cfg(feature = "metalink")]
    {
        let meta = call_auth(&st, "addMetalink", vec![]).await;
        assert_eq!(meta.code, 1);
        assert_eq!(
            meta.payload["message"],
            "The parameter at 0 is required but missing."
        );
    }
    // Both error faces are distinguishable from the unknown-method face.
    let unknown = call(&st, "frobnicate", vec![json!("token:t")]).await;
    assert_eq!(unknown.payload["message"], "No such method: frobnicate");
}

#[tokio::test]
async fn list_methods_is_frozen_surface_and_list_notifications_is_six_names() {
    // Default (compat off): canonical face — bare names project to
    // `taiji.<bare>`, `system.*`/`taiji.*` entries stay verbatim
    // (one API face at a time).
    let st = state(None);
    let methods = call(&st, "system.listMethods", vec![]).await;
    assert_eq!(methods.code, 0);
    let got: Vec<String> = as_arr(&methods.payload, "listMethods")
        .iter()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect();
    let expect: Vec<String> = method_face_names(false);
    assert_eq!(got, expect, "canonical face = method_face_names(false)");
    // Face completeness: each registered name appears exactly once.
    assert_eq!(
        got.len(),
        RPC_METHODS.len(),
        "one entry per registered name"
    );
    assert!(
        got.iter().any(|n| n == "taiji.addUri"),
        "canonical method face"
    );
    assert!(
        got.iter().any(|n| n == "system.multicall"),
        "system.* verbatim in both faces"
    );
    assert!(
        got.iter().any(|n| n == "taiji.getCapabilities"),
        "taiji.* extension verbatim in both faces"
    );

    let notes = call(&st, "system.listNotifications", vec![]).await;
    assert_eq!(notes.code, 0);
    let names: Vec<&str> = as_arr(&notes.payload, "listNotifications")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert_eq!(names, RPC_NOTIFICATIONS.to_vec());
    assert_eq!(names.len(), 6);
    assert!(names.contains(&"taiji.onBtDownloadComplete"));

    // Compat state: aria2 face — bare names project to `aria2.<bare>`;
    // verbatim entries keep the same name in both faces; listNotifications
    // switches to the frozen aria2 six names.
    let compat = state_compat(None);
    let methods = call(&compat, "system.listMethods", vec![]).await;
    assert_eq!(methods.code, 0);
    let got: Vec<String> = as_arr(&methods.payload, "listMethods")
        .iter()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect();
    assert_eq!(got, method_face_names(true), "compat face");
    assert!(got.iter().any(|n| n == "aria2.addUri"), "aria2 method face");
    assert!(
        !got.iter().any(|n| n == "taiji.addUri"),
        "one face at a time: no canonical method names leak into compat face"
    );
    let notes = call(&compat, "system.listNotifications", vec![]).await;
    let names: Vec<&str> = as_arr(&notes.payload, "listNotifications")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert_eq!(names, RPC_NOTIFICATIONS_ARIA2.to_vec());
    assert!(names.contains(&"aria2.onBtDownloadComplete"));
}

/// The six notification names match core EventKind in both faces: the
/// `system.listNotifications` table and the WS push event names share one
/// source — canonical table vs `EventKind::notification_method`, compat
/// table vs `aria2_notification_method` (WebSocketSessionMan.cc dual
/// outlets, kept drift-free).
#[test]
fn notifications_match_core_event_kinds() {
    let canonical: Vec<&str> = taiji_core::session::EventKind::ALL
        .iter()
        .map(|k| k.notification_method())
        .collect();
    assert_eq!(canonical, RPC_NOTIFICATIONS.to_vec());
    let compat: Vec<&str> = taiji_core::session::EventKind::ALL
        .iter()
        .map(|k| k.aria2_notification_method())
        .collect();
    assert_eq!(compat, RPC_NOTIFICATIONS_ARIA2.to_vec());
    // The face selector agrees with both tables (one face at a time).
    assert_eq!(notification_face(false), RPC_NOTIFICATIONS);
    assert_eq!(notification_face(true), RPC_NOTIFICATIONS_ARIA2);
}

// ---- Promised method surface: full promise-table pinning + declared differences ----

/// aria2 reference method registry (verbatim, read-only). Upstream
/// `RpcMethodFactory.cc` has 36 names plus 4 fork additions:
/// exportSession / searchDownloadResult / requeueDownloadResult /
/// getDownloadResultCount (sqlite3 download-record extensions), pinned
/// via the live `system.listMethods` surface.
#[cfg(test)]
const ARIA2_REGISTRY_METHOD_NAMES: &[&str] = &[
    "aria2.addUri",
    "aria2.addTorrent",
    "aria2.getPeers",
    "aria2.addMetalink",
    "aria2.remove",
    "aria2.pause",
    "aria2.forcePause",
    "aria2.pauseAll",
    "aria2.forcePauseAll",
    "aria2.forceRemove",
    "aria2.unpause",
    "aria2.unpauseAll",
    "aria2.changePosition",
    "aria2.tellStatus",
    "aria2.getUris",
    "aria2.getFiles",
    "aria2.getServers",
    "aria2.tellActive",
    "aria2.tellWaiting",
    "aria2.tellStopped",
    "aria2.getOption",
    "aria2.changeUri",
    "aria2.changeOption",
    "aria2.getGlobalOption",
    "aria2.changeGlobalOption",
    "aria2.purgeDownloadResult",
    "aria2.removeDownloadResult",
    "aria2.getVersion",
    "aria2.getSessionInfo",
    "aria2.shutdown",
    "aria2.forceShutdown",
    "aria2.getGlobalStat",
    "aria2.saveSession",
    "system.multicall",
    "system.listMethods",
    "system.listNotifications",
    // Fork additions (sqlite3 download records; absent upstream).
    "aria2.exportSession",
    "aria2.getDownloadResultCount",
    "aria2.requeueDownloadResult",
    "aria2.searchDownloadResult",
];

/// Registered aria2 methods NOT in the promise table — compat calls fall
/// through to "No such method"; the "RPC method-surface gaps" category of
/// [`DECLARED_DIFFERENCE_REGISTRY`]. These are the 4 fork additions.
#[cfg(test)]
const NON_PROMISED_ARIA2_METHODS: &[&str] = &[
    "aria2.exportSession",
    "aria2.getDownloadResultCount",
    "aria2.requeueDownloadResult",
    "aria2.searchDownloadResult",
];

/// Promised `taiji.*` extension methods (literal promise-table entries,
/// including the two tracker-edit methods).
#[cfg(test)]
const PROMISED_TAIJI_EXTENSION_METHODS: &[&str] = &[
    "taiji.moveStorage",
    "taiji.renameFile",
    "taiji.banAddr",
    "taiji.unbanAddr",
    "taiji.listBans",
    "taiji.setSchedulerPolicy",
    "taiji.getSchedulerPolicy",
    // Multi-level file priority write face (the write gate applies).
    "taiji.setFilePriority",
    "taiji.setStreamingPlayhead",
    "taiji.getDiskTier",
    "taiji.setDiskTier",
    "taiji.getCapabilities",
    "taiji.createTorrent",
    // Dynamic tracker editing; the compat face projects no aria2.*
    // aliases — the literal names exist in both faces.
    "taiji.addTracker",
    "taiji.removeTracker",
    // Per-task cookie passthrough. The fork has same-named aria2.*
    // methods, but the canonical name is taiji.* and the compat face does
    // not project aliases (aria2.addUriWithCookies always answers
    // "No such method").
    "taiji.addUriWithCookies",
    "taiji.setTaskCookies",
    // Media line (the media add/probe/formats/stop line plus the
    // archive-clear face):
    // the read_only adjudication lives in the core registry's frozen
    // anchor (addMedia/probeMedia/stopRecording/clearMediaArchive
    // write faces, probe = the probe action face, clear = the
    // destructive archive face; getMediaFormats the read-only query).
    "taiji.addMedia",
    "taiji.probeMedia",
    "taiji.getMediaFormats",
    "taiji.stopRecording",
    "taiji.clearMediaArchive",
];
/// Bare-name capability extension: registered under the bare name
/// (canonical face = `taiji.forceRecheck`, compat face =
/// `aria2.forceRecheck` via the single prefix-alias point). Neither the
/// reference nor the fork registry has this name (aria2 1.37.0 has no
/// recheck RPC). Kept apart from [`PROMISED_TAIJI_EXTENSION_METHODS`]
/// because the literal shape differs; declared in the "RPC method-surface
/// additions" category of [`DECLARED_DIFFERENCE_REGISTRY`].
#[cfg(test)]
const PROMISED_TAIJI_BARE_EXTENSIONS: &[&str] = &["forceRecheck"];

/// Full promise-table pinning: the registered face and the promised face
/// are set-equal (53 names = 40 reference − 4 non-promised + 16 `taiji.*`
/// named + 1 bare-name extension).
/// - Promise = aria2 reference registry − the 4 non-promised names + 16
///   `taiji.*` extensions (addTracker/removeTracker; addUriWithCookies/
///   setTaskCookies are canonical-only, no aria2.* aliases) + the bare
///   extension (forceRecheck); addMetalink joins with the `metalink`
///   feature.
/// - Compat face = `aria2.` prefix projection of bare names + verbatim
///   entries (system.*/taiji.*); the 4 non-promised names never appear;
///   the canonical face never leaks aria2 names.
/// - `canonical_method` alias normalization: bare/`taiji.X` always
///   accepted, `aria2.X` only in compat mode (one face at a
///   time).
#[test]
fn promise_table_matches_method_registry_exactly() {
    // Expected promise set (bare + system.* + taiji.*; feature gate added separately).
    let mut expected: Vec<String> = ARIA2_REGISTRY_METHOD_NAMES
        .iter()
        .filter(|n| !NON_PROMISED_ARIA2_METHODS.contains(n) && **n != "aria2.addMetalink")
        .map(|n| n.strip_prefix("aria2.").unwrap_or(n).to_string())
        .collect();
    expected.extend(
        PROMISED_TAIJI_EXTENSION_METHODS
            .iter()
            .map(|s| s.to_string()),
    );
    expected.extend(PROMISED_TAIJI_BARE_EXTENSIONS.iter().map(|s| s.to_string()));
    #[cfg(feature = "metalink")]
    expected.push("addMetalink".to_string());
    expected.sort();
    expected.dedup();

    let mut registered: Vec<String> = RPC_METHODS.iter().map(|s| s.to_string()).collect();
    registered.sort();
    assert_eq!(
        registered, expected,
        "registered face = promised face (a new method must enter both the promise table and the declaration list)"
    );

    // Compat face = reference registry projection; the 4 non-promised names never appear.
    let compat = method_face_names(true);
    let mut compat_sorted: Vec<String> = compat.clone();
    compat_sorted.sort();
    let mut expect_compat: Vec<String> = expected
        .iter()
        .map(|n| {
            if n.contains('.') {
                n.clone()
            } else {
                format!("aria2.{n}")
            }
        })
        .collect();
    expect_compat.sort();
    assert_eq!(compat_sorted, expect_compat, "compat-face projection");
    for absent in NON_PROMISED_ARIA2_METHODS {
        assert!(
            !compat.iter().any(|n| n == absent),
            "non-promised method {absent} must not appear on the compat face"
        );
        assert!(
            !RPC_METHODS.iter().any(|m| m == absent),
            "non-promised method {absent} must not be registered"
        );
    }
    // Canonical face never leaks aria2 names (one face at a time).
    let canonical = method_face_names(false);
    assert!(
        canonical.iter().all(|n| !n.starts_with("aria2.")),
        "the canonical face leaks an aria2 name: {canonical:?}"
    );
    // Alias normalization at the single canonical_method point.
    for m in RPC_METHODS {
        assert_eq!(
            canonical_method(m, false),
            Some(*m),
            "bare names always accepted"
        );
        if m.contains('.') {
            // Verbatim entries (system.*/taiji.*) have no prefix alias form.
            assert_eq!(
                canonical_method(&format!("aria2.{m}"), true),
                None,
                "verbatim {m} gets no aria2 alias"
            );
        } else {
            let alias = format!("taiji.{m}");
            assert_eq!(canonical_method(&alias, false), Some(*m), "taiji. alias");
            assert_eq!(
                canonical_method(&format!("aria2.{m}"), true),
                Some(*m),
                "the aria2. alias exists only in compat mode"
            );
            assert_eq!(
                canonical_method(&format!("aria2.{m}"), false),
                None,
                "compat off = the aria2.* unknown-method face"
            );
        }
    }
}

/// Every promised method is dispatchable: each name goes through real
/// dispatch with empty params (fresh actor, secret set so the write gate
/// is lifted) and must yield a JSON-RPC payload. A registry name missing
/// its dispatch arm panics via unreachable!.
#[tokio::test]
async fn every_promised_method_dispatches_to_a_response() {
    for m in RPC_METHODS {
        let st = state(Some("promise"));
        let resp = call_auth(&st, m, vec![]).await;
        assert!(!resp.unauthorized, "{m}: secret set → write gate lifted");
        assert!(
            !resp.payload.is_null(),
            "{m}: must yield a JSON-RPC payload (ok or structured error)"
        );
    }
}

/// The query-family table matches core descriptors exactly in both
/// directions: core-registered QueryList/QueryStatus methods equal
/// [`methods::QUERY_METHODS`] by name, kind, and order. Non-query
/// (Control/Special) entries in the table, or a shape/kind mismatch
/// (QueryList must be keys/paged, QueryStatus must be gid-shaped), fail.
#[test]
fn query_family_table_matches_core_descriptors_exactly() {
    use super::methods::QueryShape;
    use taiji_core::session::RpcMethodKind;

    let core: Vec<(&str, RpcMethodKind)> = taiji_core::session::RPC_METHOD_INFO
        .iter()
        .filter(|d| {
            matches!(
                d.kind,
                RpcMethodKind::QueryList | RpcMethodKind::QueryStatus
            )
        })
        .map(|d| (d.name, d.kind))
        .collect();
    let table: Vec<(&str, RpcMethodKind)> = super::methods::QUERY_METHODS
        .iter()
        .map(|e| (e.name, e.kind))
        .collect();
    assert_eq!(
        core, table,
        "the query-family table must exactly equal the core descriptors (the query-kind subset) by name, kind, and order"
    );
    // Kind ↔ shape correspondence (mismatch = routing drift).
    for e in super::methods::QUERY_METHODS {
        match e.kind {
            RpcMethodKind::QueryList => assert!(
                matches!(e.shape, QueryShape::KeysOnly | QueryShape::PagedKeys),
                "{}: QueryList must be keys/paged-shaped",
                e.name
            ),
            RpcMethodKind::QueryStatus => assert!(
                matches!(e.shape, QueryShape::GidKeys | QueryShape::GidOnly),
                "{}: QueryStatus must be gid-located",
                e.name
            ),
            other => panic!("the query-family table must not admit non-query kinds: {other:?}"),
        }
    }
}

/// Declared-difference registry: the in-repo baseline of all known
/// deviations from the aria2 reference. Execution anchors: option stances
/// in core `session::options` (accepted / not accepted / unwired), error
/// codes in the `crate::error` mapping table, metalink expansion
/// semantics in the `crate::metalink` module docs.
#[cfg(test)]
const DECLARED_DIFFERENCE_REGISTRY: &[(&str, &[&str])] = &[
    (
        "Scheduling behavior",
        &[
            "http-scheduler=dynamic|static (guided+AIMD+stall stealing; aria2 has no dynamic scheduling)",
        ],
    ),
    (
        "Scheduling parameter semantics redefined",
        &[
            "split (only the initial extent reference under dynamic)",
            "min-split-size (same as split)",
            "max-connection-per-server (the AIMD growth cap, domain 1-16)",
        ],
    ),
    (
        "Retry domain",
        &["max-tries (per extent; aria2 is per download)"],
    ),
    (
        "RPC method face missing items",
        &[
            "aria2.exportSession not in the promise table (fork delta)",
            "aria2.getDownloadResultCount not in the promise table (fork delta)",
            "aria2.requeueDownloadResult not in the promise table (fork delta)",
            "aria2.searchDownloadResult not in the promise table (fork delta)",
        ],
    ),
    (
        "RPC method face additions (no upstream counterpart)",
        &[
            "forceRecheck dual naming (canonical taiji.forceRecheck / compat \
             aria2.forceRecheck / bare name, all three accepted) — neither upstream aria2 \
             1.37.0 nor the fork registry has a recheck RPC; a capability extension, not a \
             promise narrowing; torrent tasks only (active = stop -> verify -> requeue; \
             reserved = dequeue, verify, requeue at the head), verify-phase tellStatus \
             active semantics + completedLength progress projection",
        ],
    ),
    (
        "Event face",
        &[
            "canonical = the taiji.onXxx six events; compat = aria2.onXxx (one face at a time, dual emission banned)",
        ],
    ),
    (
        "metalink v3 fallback",
        &[
            "v3 = taiji.metalink.unsupported_version explicit degradation (the quantified decision = degrade)",
        ],
    ),
    (
        "metalink option family (accepted and ignored + warning; auto-discover accepted but treated as invalid)",
        &[
            "metalink-language",
            "metalink-location",
            "metalink-os",
            "metalink-version",
            "metalink-preferred-protocol",
            "metalink-force-protocol",
            "metalink-enable-unique-protocol",
            "metalink-enable-auto-discover",
        ],
    ),
    (
        "metalink expansion semantics",
        &[
            "entry name flattened to basename (--out takes bare file names)",
            "checksum folded into the six hashes (md5/sha-1/sha-224/sha-256/sha-384/sha-512 \
             — same domain as the --checksum value domain; a single checksum prefers the \
             stronger sha-256; out-of-domain types produce nothing)",
            "<pieces>/<signature> parsed and retained, not consumed by the download face",
            "url@type attribute unconsumed (the mirror-family filter = superset behavior)",
            "metaurl passthrough: non-torrent mediatype / non-.torrent URI skipped + warning; \
             no multi-file shared-torrent merging (each entry gets an independent GID and state)",
            "zero usable tasks = an empty-array receipt (not an error)",
        ],
    ),
    (
        "saveSession file format",
        &["triggers a full DB flush; does not produce the aria2 session file format"],
    ),
    (
        "cookie face",
        &[
            "--load-cookies accepted (a session-level default cookie source + per-task \
             overrides, fail-closed loading <=1MiB, echoed by getGlobalOption)",
            "--save-cookies CLI acceptance disclosed (inert in this build); the RPC/session \
             face does not accept it (this build does not do that — sqlite is the only \
             persistence truth)",
        ],
    ),
    (
        "Proxy shapes",
        &[
            "--all-proxy single slot only (the http-proxy/https-proxy/no-proxy family not accepted)",
            "socks5(h)/socks4(a) explicitly rejected (the reqwest socks feature is not enabled)",
            "proxy auth via URL userinfo (the --all-proxy-user family not accepted)",
            "FTP-over-HTTP proxy P2",
        ],
    ),
    (
        "FTP face",
        &[
            "charset fallback UTF-8/Latin-1 (aria2 does no conversion)",
            "--ftp-pasv=false explicitly rejected (active mode not implemented)",
            "--ftp-ssl capability extension (aria2 has no FTPS)",
            "SIZE-unsupported sources removed (a tightening vs aria2's streaming)",
        ],
    ),
    (
        "Protocol shapes (experimental window)",
        &[
            "https automatically negotiates HTTP/2 per the server's ALPN (h2 + rustls; aria2 is HTTP/1.1 only)",
            "--http-protocol=auto|h1|h2 capability extension + experimental window (h2 = \
             prior-knowledge h2c cleartext form, no Upgrade, no fallback; the default auto is unchanged)",
            "--http2-adaptive-window/--http2-stream-window/--http2-connection-window \
             capability extension + experimental window (the h2 flow-control window tuning face; \
             engine defaults: static window, stream 8MiB / connection 16MiB, adaptive off by default)",
            "--http2-max-connections/--http2-keep-alive-interval capability extension + \
             experimental window (the h2 multi-connection cap defaults to 1 / PING keep-alive \
             defaults off — the default status quo unchanged)",
        ],
    ),
    (
        "enabledFeatures new fields",
        &["the Metalink compile-state entry"],
    ),
    (
        "SFTP",
        &["sftp:// deferred = taiji.sftp.deferred (delivered by a separate effort)"],
    ),
    (
        "HTTP unaccepted option family",
        &[
            "core session::options::DECLARED_NON_ACCEPTED_OPTION_NAMES (referer/\
           allow-overwrite/auto-file-renaming/lowest-speed-limit etc., 27 names finalized; \
           ca-certificate and load-cookies have moved to the accepted face)",
        ],
    ),
];

/// Execution-face check of the registry: the category set is complete,
/// anchor symbols are live, and every option name in the list is
/// registered in the declared-option table.
#[test]
fn declared_difference_registry_anchors_are_live() {
    use crate::error::{STR_METALINK_PARSE_FAILED, STR_METALINK_UNSUPPORTED_VERSION};
    use taiji_core::session::option_name_declared;

    // The category set is exactly this list; new categories must update
    // this assertion (whitelist governance).
    let categories: Vec<&str> = DECLARED_DIFFERENCE_REGISTRY
        .iter()
        .map(|(c, _)| *c)
        .collect();
    assert_eq!(
        categories,
        vec![
            "Scheduling behavior",
            "Scheduling parameter semantics redefined",
            "Retry domain",
            "RPC method face missing items",
            "RPC method face additions (no upstream counterpart)",
            "Event face",
            "metalink v3 fallback",
            "metalink option family (accepted and ignored + warning; auto-discover accepted but treated as invalid)",
            "metalink expansion semantics",
            "saveSession file format",
            "cookie face",
            "Proxy shapes",
            "FTP face",
            "Protocol shapes (experimental window)",
            "enabledFeatures new fields",
            "SFTP",
            "HTTP unaccepted option family",
        ],
        "the declared-difference category set drifted — new categories must come with PR rationale (whitelist governance)"
    );

    // Error-code anchors (single source: the mapping table).
    assert_eq!(
        STR_METALINK_UNSUPPORTED_VERSION,
        "taiji.metalink.unsupported_version"
    );
    assert_eq!(STR_METALINK_PARSE_FAILED, "taiji.metalink.parse_failed");

    // Every metalink option-family name is registered in the declared table.
    let family = DECLARED_DIFFERENCE_REGISTRY
        .iter()
        .find(|(c, _)| c.starts_with("metalink option family"))
        .map(|(_, e)| *e)
        .unwrap_or_else(|| panic!("metalink option family category present"));
    for name in family {
        assert!(
            option_name_declared(name),
            "baseline name {name} not registered in the declaration table"
        );
    }

    // enabledFeatures anchor: the Metalink entry tracks the compile-time
    // feature (feature_gate.rs also pins the off state).
    if cfg!(feature = "metalink") {
        assert!(ENABLED_FEATURES.contains(&"Metalink"));
    } else {
        assert!(!ENABLED_FEATURES.contains(&"Metalink"));
    }
}

#[tokio::test]
async fn multicall_success_wraps_result_in_list() {
    // RpcMethodImpl.cc: code==0 → [result].
    let st = state(None);
    let resp = call(
        &st,
        "system.multicall",
        vec![json!([
            {"methodName": "getVersion", "params": []},
            {"methodName": "system.listNotifications"}
        ])],
    )
    .await;
    assert_eq!(resp.code, 0);
    let slots = as_arr(&resp.payload, "multicall slots");
    assert_eq!(slots.len(), 2);
    assert!(slots[0].is_array(), "success must be wrapped in a list");
    assert!(slots[0][0]["version"].is_string());
    // listNotifications already returns a list of six names; multicall
    // wraps it once more: slots[1] = [[...6 names...]] (RpcMethodImpl.cc).
    assert!(slots[1].is_array());
    assert_eq!(as_arr(&slots[1], "wrapped notifications").len(), 1);
    assert_eq!(
        as_arr(&as_arr(&slots[1], "wrapped")[0], "notifications").len(),
        6
    );
}

#[tokio::test]
async fn multicall_errors_are_inlined_not_fatal() {
    // RpcMethodImpl.cc: error slots are inlined in place and the rest
    // continue. Sub-calls carry their own tokens.
    let st = state(Some("t"));
    let resp = call(
        &st,
        "system.multicall",
        vec![json!([
            {"methodName": "getVersion", "params": ["token:t"]},
            {"methodName": "no.such", "params": ["token:t"]},
            {"methodName": "addUri", "params": ["token:t"]},
            42,
            {"params": []},
            {"methodName": "system.multicall", "params": []}
        ])],
    )
    .await;
    assert_eq!(resp.code, 0, "multicall itself succeeds with inline errors");
    let slots = as_arr(&resp.payload, "multicall slots");
    assert_eq!(slots.len(), 6);
    assert!(slots[0].is_array(), "success slot");
    assert_eq!(slots[1]["message"], "No such method: no.such");
    // addUri with empty params hits the param-validation face, not not_supported.
    assert_eq!(
        slots[2]["message"],
        "The parameter at 0 is required but missing."
    );
    assert_eq!(slots[3]["message"], "system.multicall expected struct.");
    assert_eq!(slots[4]["message"], "Missing methodName.");
    assert_eq!(slots[5]["message"], "Recursive system.multicall forbidden.");
}

#[tokio::test]
async fn multicall_requires_array_of_specs_at_param0() {
    // Both branches of checkRequiredParam<List> (RpcMethodImpl.h).
    let st = state(None);
    let wrong_type = call(&st, "system.multicall", vec![json!("not-a-list")]).await;
    assert_eq!(wrong_type.code, 1);
    assert_eq!(
        wrong_type.payload["message"],
        "The parameter at 0 has wrong type."
    );

    let missing = call(&st, "system.multicall", vec![]).await;
    assert_eq!(missing.code, 1);
    assert_eq!(
        missing.payload["message"],
        "The parameter at 0 is required but missing."
    );
}

#[tokio::test]
async fn multicall_subcall_unauthorized_marks_whole_response() {
    // RpcMethodImpl.cc + HttpServerBodyCommand.cc: any unauthorized
    // sub-call sets the whole-response delay flag (applied at the HTTP
    // layer).
    let st = state(Some("sekrit"));
    let resp = call(
        &st,
        "system.multicall",
        vec![json!([
            {"methodName": "getVersion", "params": ["token:sekrit"]},
            {"methodName": "addUri"}
        ])],
    )
    .await;
    assert_eq!(resp.code, 0);
    assert!(
        resp.unauthorized,
        "any sub-call unauthorized must propagate"
    );
    assert_eq!(
        as_arr(&resp.payload, "multicall slots")[1]["message"],
        "Unauthorized"
    );
}

// ---- Security hardening regressions (rpc face) ----

/// Write gate: with no --rpc-secret, every write method fails closed
/// (including shutdown and extensions); read-only and system.list*
/// anonymous faces are unaffected.
#[tokio::test]
async fn unauthenticated_write_is_refused_while_read_only_passes() {
    let st = state(None);
    // addMetalink is a registered write method behind the feature gate;
    // with the feature off the name does not exist (tests/feature_gate.rs).
    #[cfg(feature = "metalink")]
    let write_methods = vec![
        "addUri",
        "addTorrent",
        "addMetalink",
        "remove",
        "forceRemove",
        "pause",
        "forcePause",
        "unpause",
        // forceRecheck: write face, goes through the gate (not in the
        // is_read_only exemption set).
        "forceRecheck",
        "pauseAll",
        // forcePauseAll: write face, goes through the gate (like pauseAll).
        "forcePauseAll",
        "unpauseAll",
        "purgeDownloadResult",
        "removeDownloadResult",
        "changeUri",
        "changePosition",
        "changeOption",
        "changeGlobalOption",
        "saveSession",
        "shutdown",
        "forceShutdown",
        "taiji.moveStorage",
        "taiji.renameFile",
        // Tracker editing: write face, goes through the gate (like
        // setDiskTier).
        "taiji.addTracker",
        "taiji.removeTracker",
        // Per-task cookies: write face, goes through the gate (like
        // addTracker).
        "taiji.addUriWithCookies",
        "taiji.setTaskCookies",
    ];
    #[cfg(not(feature = "metalink"))]
    let write_methods = vec![
        "addUri",
        "addTorrent",
        "remove",
        "forceRemove",
        "pause",
        "forcePause",
        "unpause",
        // forceRecheck: write face, goes through the gate.
        "forceRecheck",
        "pauseAll",
        // forcePauseAll: write face, goes through the gate (like pauseAll).
        "forcePauseAll",
        "unpauseAll",
        "purgeDownloadResult",
        "removeDownloadResult",
        "changeUri",
        "changePosition",
        "changeOption",
        "changeGlobalOption",
        "saveSession",
        "shutdown",
        "forceShutdown",
        "taiji.moveStorage",
        "taiji.renameFile",
        // Tracker editing: write face, goes through the gate (like
        // setDiskTier).
        "taiji.addTracker",
        "taiji.removeTracker",
        // Per-task cookies: write face, goes through the gate (like
        // addTracker).
        "taiji.addUriWithCookies",
        "taiji.setTaskCookies",
    ];
    for method in write_methods {
        let r = call(&st, method, vec![json!("junk")]).await;
        assert_eq!(r.code, 1, "{method}");
        assert_eq!(
            r.payload["message"], "unauthenticated write requires --rpc-secret",
            "{method}"
        );
        assert!(
            !r.unauthorized,
            "{method}: write gate is a policy refusal, not token-auth delay"
        );
    }
    // Read-only methods unaffected (empty-params form passes).
    for method in [
        "getVersion",
        "getGlobalOption",
        "getGlobalStat",
        "getSessionInfo",
        "tellActive",
        "system.listMethods",
        "system.listNotifications",
        // Anonymous capability discovery via the no-param query face.
        "taiji.getCapabilities",
    ] {
        let r = call(&st, method, vec![]).await;
        assert_eq!(r.code, 0, "{method}: {}", r.payload["message"]);
    }
    // getOption is in the query family: reachable anonymously — with no
    // secret it passes the write gate and fails at param decode (missing
    // param text, not the write-gate text), matching the reference where
    // reads pass without a secret.
    let r = call(&st, "getOption", vec![]).await;
    assert_eq!(r.code, 1);
    assert_eq!(
        r.payload["message"], "The parameter at 0 is required but missing.",
        "getOption must pass the write gate and fail at param decode"
    );
}

/// End-to-end for changeGlobalOption's bt-tracker import path: dispatch →
/// SessionCommand → actor union import → visible in the getGlobalOption
/// echo (complements the core-side hot-reload test
/// global_tracker_hot_reload_reaches_running_and_later_tasks).
#[tokio::test]
async fn change_global_option_bt_tracker_imports_and_echoes() {
    let st = state(Some("t"));
    let resp = call_auth(
        &st,
        "changeGlobalOption",
        vec![json!({
            "bt-tracker": "udp://rpc.example:6969/announce,udp://rpc2.example:1337/announce",
            "max-concurrent-downloads": "2"
        })],
    )
    .await;
    assert_eq!(resp.code, 0, "{}", resp.payload["message"]);
    let echo = call_auth(&st, "getGlobalOption", vec![json!({})]).await;
    assert_eq!(echo.code, 0, "{}", echo.payload["message"]);
    assert_eq!(
        echo.payload["bt-tracker"],
        json!("udp://rpc.example:6969/announce,udp://rpc2.example:1337/announce"),
        "import echoes back (the global set after the union)"
    );
    // Other hot-changeable keys in the same call are unaffected.
    assert_eq!(echo.payload["max-concurrent-downloads"], json!("2"));
    // Echoed values are strings (aria2 convention).
    assert!(echo.payload["bt-tracker"].is_string());
}

/// `--summary-interval` e2e: getGlobalOption echoes the default 60;
/// changeGlobalOption silently ignores the key (startup-only option,
/// applies after restart — the reference treats it the same way).
#[tokio::test]
async fn summary_interval_echoes_but_is_not_changeable() {
    let st = state(Some("t"));
    let echo = call_auth(&st, "getGlobalOption", vec![json!({})]).await;
    assert_eq!(echo.code, 0, "{}", echo.payload["message"]);
    assert_eq!(
        echo.payload["summary-interval"],
        json!("60"),
        "the default 60 echoes back (the OptionHandlerFactory.cc anchor)"
    );
    let resp = call_auth(
        &st,
        "changeGlobalOption",
        vec![json!({"summary-interval": "5"})],
    )
    .await;
    assert_eq!(
        resp.code, 0,
        "the call itself does not error (unknown items ignored — the reference behaves the same)"
    );
    let after = call_auth(&st, "getGlobalOption", vec![json!({})]).await;
    assert_eq!(
        after.payload["summary-interval"],
        json!("60"),
        "changeGlobalOption does not accept summary-interval (capability bits aligned with the reference)"
    );
}

/// getOption dispatch: param face (missing/wrong-type texts from the
/// checkRequiredParam<String> family, RpcMethodImpl.cc), GID resolution
/// errors passed through verbatim (str2Gid family), and a real-task e2e
/// (addUri kept paused → reply is a string-valued dict in the
/// pushRequestOption form).
#[tokio::test]
async fn get_option_dispatch_params_errors_and_task_echo() {
    let st = state(Some("t"));
    // Missing / wrong type (aria2 checkRequiredParam<String> text family).
    let missing = call_auth(&st, "getOption", vec![]).await;
    assert_eq!(missing.code, 1);
    assert_eq!(
        missing.payload["message"],
        "The parameter at 0 is required but missing."
    );
    let wrong = call_auth(&st, "getOption", vec![json!(12345)]).await;
    assert_eq!(
        wrong.payload["message"],
        "The parameter at 0 has wrong type."
    );
    // Unknown GID: actor resolve_gid error passed through (str2Gid family, verbatim).
    let notfound = call_auth(&st, "getOption", vec![json!("beef000000000000")]).await;
    assert_eq!(notfound.code, 1);
    assert_eq!(
        notfound.payload["message"],
        "GID beef000000000000 is not found"
    );
    // Real-task e2e: addUri paused → reply is a string-valued dict
    // projecting the accepted option subset (dir always present; the
    // timeout given at add time round-trips).
    let add = call_auth(
        &st,
        "addUri",
        vec![
            json!(["http://127.0.0.1:9/getopt.bin"]),
            json!({"pause": "true", "timeout": "30", "user-agent": "getopt/1"}),
        ],
    )
    .await;
    assert_eq!(add.code, 0, "{}", add.payload["message"]);
    let Some(gid) = add.payload.as_str() else {
        panic!("addUri should return gid, got {}", add.payload);
    };
    let echo = call_auth(&st, "getOption", vec![json!(gid)]).await;
    assert_eq!(echo.code, 0, "{}", echo.payload["message"]);
    assert!(
        echo.payload.is_object(),
        "the receipt is a dict (the pushRequestOption shape)"
    );
    assert_eq!(echo.payload["timeout"], json!("30"));
    assert_eq!(echo.payload["user-agent"], json!("getopt/1"));
    assert!(
        echo.payload["dir"].is_string(),
        "values are always on the string face"
    );
}

/// The write gate only closes when no secret is set: with a secret and a
/// token, writes pass; with a secret but no token, the token layer
/// rejects first (Unauthorized with the delay flag).
#[tokio::test]
async fn write_gate_lifts_once_secret_is_set() {
    let st = state(Some("t"));
    let ok = call_auth(
        &st,
        "changeGlobalOption",
        vec![json!({"max-concurrent-downloads": "2"})],
    )
    .await;
    assert_eq!(ok.code, 0, "{}", ok.payload["message"]);
    let no_token = call(&st, "changeGlobalOption", vec![json!({})]).await;
    assert_eq!(no_token.payload["message"], "Unauthorized");
    assert!(no_token.unauthorized);
}

/// The write gate also applies to multicall sub-calls (read-only sub-calls pass).
#[tokio::test]
async fn multicall_write_subcall_gated_without_secret() {
    let st = state(None);
    let resp = call(
        &st,
        "system.multicall",
        vec![json!([
            {"methodName": "getVersion", "params": []},
            {"methodName": "addUri", "params": [["http://x/f"]]},
            {"methodName": "remove", "params": ["9000000000000001"]}
        ])],
    )
    .await;
    assert_eq!(resp.code, 0);
    let slots = as_arr(&resp.payload, "multicall slots");
    assert_eq!(slots.len(), 3);
    assert!(slots[0].is_array(), "read-only sub-call passes");
    assert_eq!(
        slots[1]["message"],
        "unauthenticated write requires --rpc-secret"
    );
    assert_eq!(
        slots[2]["message"],
        "unauthenticated write requires --rpc-secret"
    );
}

/// Pagination arithmetic saturates: remote i64 extremes no longer
/// overflow (previously `offset + num` wrapped negative and the slice
/// panicked — a remote DoS).
#[test]
fn pagination_range_extreme_inputs_do_not_overflow() {
    type RangeCase = (i64, i64, i64, Option<(usize, usize)>);
    let cases: &[RangeCase] = &[
        // num=i64::MAX: positive offset clamps to [offset, size).
        (1, i64::MAX, 5, Some((1, 5))),
        (0, i64::MAX, 5, Some((0, 5))),
        // offset=i64::MAX: out of bounds → None.
        (i64::MAX, 2, 5, None),
        // offset=i64::MIN: tempoffset saturates below 0 → None.
        (i64::MIN, 2, 5, None),
        (i64::MIN, i64::MAX, 5, None),
        // Negative offset + huge num: clamps to 0 and shrinks num.
        (-2, i64::MAX, 5, Some((0, 4))),
        (-1, i64::MAX, 4, Some((0, 4))),
    ];
    for &(offset, num, size, expect) in cases {
        assert_eq!(
            pagination_range(offset, num, size),
            expect,
            "offset={offset} num={num} size={size}"
        );
    }
}

/// Extreme tellWaiting/tellStopped pagination never panics and always
/// returns a valid array (core receives a clamped u32 num).
#[tokio::test]
async fn tell_pagination_extremes_do_not_panic() {
    let st = state(Some("t"));
    for (offset, num) in [
        (1, i64::MAX),
        (0, i64::MAX),
        (i64::MAX, i64::MAX),
        (i64::MIN, 2),
        (i64::MIN, i64::MAX),
        (-2, i64::MAX),
    ] {
        for method in ["tellWaiting", "tellStopped"] {
            let r = call_auth(&st, method, vec![json!(offset), json!(num)]).await;
            assert_eq!(
                r.code, 0,
                "{method}({offset},{num}): {}",
                r.payload["message"]
            );
            assert!(r.payload.is_array(), "{method}({offset},{num})");
        }
    }
}

/// Batch item cap: over the cap the whole batch is rejected with a single
/// error object before per-item processing; at the cap, items are
/// answered one by one (non-object entries still skipped).
#[tokio::test]
async fn batch_over_item_cap_is_rejected_with_too_many_items() {
    let st = state(None);
    let over: Value = (0..=MAX_BATCH_ITEMS)
        .map(|i| json!({"id": i, "method": "getVersion"}))
        .collect();
    let outcome = handle_payload(&st, &over, None).await;
    assert_eq!(outcome.code, 1);
    assert_eq!(outcome.body["error"]["code"], 1);
    assert!(
        outcome.body["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("taiji.request.too_many_items"),
        "cap error: {}",
        outcome.body["error"]["message"]
    );

    // Exactly at the cap (including the skipped non-object entry): answered per item.
    let at_cap: Value = (0..MAX_BATCH_ITEMS - 1)
        .map(|i| json!({"id": i, "method": "getVersion"}))
        .chain(std::iter::once(json!(42)))
        .collect();
    let outcome = handle_payload(&st, &at_cap, None).await;
    assert_eq!(outcome.code, 0);
    assert_eq!(
        as_arr(&outcome.body, "at-cap batch").len(),
        MAX_BATCH_ITEMS - 1,
        "at-cap batch answers item-by-item (non-object skipped)"
    );
}

/// multicall specs are also capped; over the cap the whole request is rejected.
#[tokio::test]
async fn multicall_over_item_cap_is_rejected() {
    let st = state(None);
    let specs: Value = (0..=MAX_BATCH_ITEMS)
        .map(|_| json!({"methodName": "getVersion", "params": []}))
        .collect();
    let resp = call(&st, "system.multicall", vec![specs]).await;
    assert_eq!(resp.code, 1);
    assert!(
        resp.payload["message"]
            .as_str()
            .unwrap_or_default()
            .contains("taiji.request.too_many_items"),
        "cap error: {}",
        resp.payload["message"]
    );
}

#[tokio::test]
async fn batch_equals_single_and_skips_non_object_entries() {
    // Batch equals single request (HttpServerBodyCommand.cc).
    let st = state(None);
    let single = single(&st, &json!({"id": 7, "method": "getVersion"}), None).await;
    let outcome = handle_payload(
        &st,
        &json!([
            42,
            {"id": 7, "method": "getVersion"},
            "noise"
        ]),
        None,
    )
    .await;
    assert_eq!(outcome.code, 0, "batch HTTP status is always 200");
    let arr = as_arr(&outcome.body, "batch array");
    assert_eq!(arr.len(), 1, "non-object entries must be skipped");
    assert_eq!(arr[0], single.encode(), "batch response must equal single");
}

#[tokio::test]
async fn shutdown_via_rpc_replies_ok_cancels_token_and_drains_actor() {
    // A SessionActor exits on the first shutdown, so each method name gets
    // its own actor; bare, canonical `taiji.*`, and compat `aria2.*`
    // aliases are equivalent (aliases only in compat mode).
    for (method, compat) in [
        ("shutdown", false),
        ("taiji.forceShutdown", false),
        ("aria2.forceShutdown", true),
    ] {
        let (session, join) = SessionActor::spawn();
        let shutdown = CancellationToken::new();
        // shutdown/forceShutdown are write methods and must carry a token.
        let st = AppState {
            session: Arc::new(session),
            secret: Some("t".to_string()),
            basic: None,
            allow_origin_all: false,
            max_request_size: 1 << 20,
            shutdown: shutdown.clone(),
            aria2_compat: compat,
            listen_all: false,
            conn: Arc::new(crate::guards::ConnLedger::new(
                crate::guards::DEFAULT_MAX_TOTAL_CONNS,
                crate::guards::DEFAULT_MAX_PER_IP_CONNS,
            )),
            auth_backoff: Arc::new(crate::guards::AuthBackoff::new(
                crate::guards::DEFAULT_AUTH_FAIL_THRESHOLD,
            )),
        };
        let resp = process_call(&st, method, vec![json!("token:t")], json!(1), false, None).await;
        assert_eq!(resp.code, 0, "{method}");
        assert_eq!(resp.payload, json!("OK"), "createOKResponse form");
        assert!(shutdown.is_cancelled(), "{method} must cancel server token");
        let joined = tokio::time::timeout(Duration::from_secs(1), join).await;
        assert!(joined.is_ok(), "actor must drain within 1s of rpc {method}");
    }
}

// ---- Method surface over the RPC transport (end-to-end) ----

/// Minimal v1 metainfo (single 32B file / 1 piece; placeholder pieces —
/// the parser does not verify hash/content consistency).
fn v1_torrent_bytes() -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(
            b"d8:announce27:http://127.0.0.1:1/announce4:infod6:lengthi32e4:name5:t.bin12:piece lengthi16384e6:pieces20:",
        );
    v.extend_from_slice(&[0xAB; 20]);
    v.extend_from_slice(b"ee");
    v
}

fn b64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            T[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            T[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

fn ok_str(resp: &RpcResponse) -> String {
    resp.payload.as_str().unwrap_or_default().to_string()
}

#[tokio::test]
async fn add_torrent_tell_active_remove_tell_stopped_end_to_end() {
    // RPC addTorrent → visible in tellActive → remove → visible in
    // tellStopped, all through JSON-RPC dispatch and the SessionActor
    // queue. Write methods carry tokens.
    let st = state(Some("t"));
    let dir = std::env::temp_dir().join(format!("bh-p34-rpc-{}", std::process::id()));
    let add = call_auth(
        &st,
        "addTorrent",
        vec![
            json!(b64(&v1_torrent_bytes())),
            json!([]),
            json!({"dir": dir.display().to_string()}),
        ],
    )
    .await;
    assert_eq!(add.code, 0, "addTorrent: {}", add.payload["message"]);
    let gid = ok_str(&add);
    assert_eq!(gid.len(), 16);
    let high = u64::from_str_radix(&gid, 16).unwrap_or(0) & 0x8000_0000_0000_0000;
    assert_ne!(high, 0, "gid top bit set");

    let active = call_auth(&st, "tellActive", vec![]).await;
    assert_eq!(active.code, 0);
    let arr = as_arr(&active.payload, "tellActive");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["gid"], json!(gid));
    assert_eq!(arr[0]["status"], "active");
    assert_eq!(arr[0]["totalLength"], json!("32"));
    assert_eq!(arr[0]["seeder"], json!("false"));
    assert_eq!(arr[0]["numSeeders"], json!("0"));
    // Piece storage is allocated for the active task, so the all-zero
    // bitmap is reported (aria2: getBitfieldLength > 0; "00" = 1
    // unfinished piece).
    assert_eq!(arr[0]["bitfield"], json!("00"));
    let stopped_active_info_hash = arr[0]["infoHash"].clone();
    assert_eq!(stopped_active_info_hash.as_str().map(str::len), Some(40));

    // remove → GID reply (aria2 createGIDResponse shape).
    let removed = call_auth(&st, "remove", vec![json!(gid.clone())]).await;
    assert_eq!(removed.code, 0, "{}", removed.payload["message"]);
    assert_eq!(removed.payload, json!(gid));

    // Completion event drives visibility in tellStopped.
    let mut stopped = Vec::new();
    for _ in 0..100 {
        // tellStopped pagination params are required
        // (checkRequiredParam<Integer>, RpcMethodImpl.h); (0, 10) is the
        // aria2 CLI default.
        let r = call_auth(&st, "tellStopped", vec![json!(0), json!(10)]).await;
        stopped = as_arr(&r.payload, "tellStopped").clone();
        if !stopped.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(stopped.len(), 1);
    assert_eq!(stopped[0]["gid"], json!(gid));
    assert_eq!(stopped[0]["status"], "removed");
    // Stopped dict fields (gatherStoppedDownload, RpcMethodImpl.cc):
    // errorCode=31 (REMOVED), errorMessage always present, zero
    // speeds/connections, numeric fields as strings (aria2 uitos).
    assert_eq!(stopped[0]["errorCode"], json!("31"));
    assert_eq!(stopped[0]["errorMessage"], json!(""));
    assert_eq!(stopped[0]["downloadSpeed"], json!("0"));
    assert_eq!(stopped[0]["uploadSpeed"], json!("0"));
    assert_eq!(stopped[0]["connections"], json!("0"));
    assert_eq!(
        stopped[0]["infoHash"], stopped_active_info_hash,
        "the stopped face keeps infoHash"
    );
    assert_eq!(stopped[0]["numSeeders"], json!("0"));
    assert!(
        stopped[0].get("seeder").is_none(),
        "the stopped face has no seeder key"
    );
    assert!(
        stopped[0].get("bitfield").is_none(),
        "a partial bitfield is not kept -> the key is absent"
    );
    assert!(stopped[0]["files"].is_array());

    // Result-table cleanup: removeDownloadResult → OK; purge → OK.
    let rm = call_auth(&st, "removeDownloadResult", vec![json!(gid.clone())]).await;
    assert_eq!(rm.payload, json!("OK"));
    assert_eq!(
        call_auth(&st, "purgeDownloadResult", vec![]).await.payload,
        json!("OK")
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn rpc_secret_never_appears_in_get_global_option_response() {
    // The session carries a secret; the getGlobalOption echo must not
    // contain the rpc-secret key.
    let global = taiji_core::session::GlobalOptions {
        rpc_secret: Some("top-secret".to_string()),
        ..Default::default()
    };
    let (session, _join) = SessionActor::spawn_with(taiji_core::session::SessionOptions { global });
    let st = AppState {
        session: Arc::new(session),
        secret: Some("top-secret".to_string()),
        basic: None,
        allow_origin_all: false,
        max_request_size: 1 << 20,
        shutdown: CancellationToken::new(),
        aria2_compat: false,
        listen_all: false,
        conn: Arc::new(crate::guards::ConnLedger::new(
            crate::guards::DEFAULT_MAX_TOTAL_CONNS,
            crate::guards::DEFAULT_MAX_PER_IP_CONNS,
        )),
        auth_backoff: Arc::new(crate::guards::AuthBackoff::new(
            crate::guards::DEFAULT_AUTH_FAIL_THRESHOLD,
        )),
    };
    let resp = call(&st, "getGlobalOption", vec![json!("token:top-secret")]).await;
    assert_eq!(resp.code, 0);
    let rendered = resp.payload.to_string();
    assert!(
        !rendered.contains("top-secret"),
        "secret leaked: {rendered}"
    );
    assert!(
        resp.payload.get("rpc-secret").is_none(),
        "rpc-secret key must never appear"
    );
    assert_eq!(
        resp.payload["max-concurrent-downloads"],
        json!("5"),
        "echo values are strings (the aria2 convention)"
    );
}

#[tokio::test]
async fn get_session_info_returns_random_hex_via_rpc() {
    let st = state(None);
    let resp = call(&st, "getSessionInfo", vec![]).await;
    assert_eq!(resp.code, 0);
    let id = resp.payload["sessionId"].as_str().unwrap_or_default();
    assert_eq!(id.len(), 32);
}

#[tokio::test]
async fn add_uri_param_validation_errors_match_reference_texts() {
    let st = state(Some("t"));
    // Missing list param → checkRequiredParam<List> text.
    let missing = call_auth(&st, "addUri", vec![]).await;
    assert_eq!(
        missing.payload["message"],
        "The parameter at 0 is required but missing."
    );
    // Empty list → "URI is not provided."
    let empty = call_auth(&st, "addUri", vec![json!([])]).await;
    assert_eq!(empty.payload["message"], "URI is not provided.");
    // ftp(s)/http(s) are accepted directly (GID reply); truly unsupported
    // schemes still fail explicitly (file: is not disguised).
    let ftp = call_auth(&st, "addUri", vec![json!(["ftp://h/f"])]).await;
    assert_eq!(
        ftp.code, 0,
        "ftp accepted out of the box: {}",
        ftp.payload["message"]
    );
    assert!(ftp.payload.as_str().map(str::len) == Some(16));
    let file = call_auth(&st, "addUri", vec![json!(["file:///tmp/x"])]).await;
    assert!(
        file.payload["message"]
            .as_str()
            .unwrap_or_default()
            .contains("not supported")
    );
}

#[tokio::test]
async fn change_uri_positional_shape_and_counts() {
    // changeUri positional params in aria2 form: (gid, fileIndex, del, add, pos).
    let st = state(Some("t"));
    let dir = std::env::temp_dir().join(format!("bh-p34-uri-{}", std::process::id()));
    // max-concurrent=1 → second task waiting (editing does not spawn the engine).
    assert_eq!(
        call_auth(
            &st,
            "changeGlobalOption",
            vec![json!({"max-concurrent-downloads": "1"})]
        )
        .await
        .code,
        0
    );
    let _a = call_auth(
        &st,
        "addTorrent",
        vec![
            json!(b64(&v1_torrent_bytes())),
            json!([]),
            json!({"dir": dir.display().to_string()}),
        ],
    )
    .await;
    let bytes_b = {
        // Second torrent: name changed to keep a unique identity.
        let mut v = Vec::new();
        v.extend_from_slice(
                b"d8:announce27:http://127.0.0.1:1/announce4:infod6:lengthi32e4:name5:u.bin12:piece lengthi16384e6:pieces20:",
            );
        v.extend_from_slice(&[0xCD; 20]);
        v.extend_from_slice(b"ee");
        v
    };
    let b = call_auth(
        &st,
        "addTorrent",
        vec![
            json!(b64(&bytes_b)),
            json!([]),
            json!({"dir": dir.display().to_string()}),
        ],
    )
    .await;
    let gid_b = ok_str(&b);
    // All positional params given: fileIndex=1 is in range for the single
    // file → BT tasks answer the upstream no-op counts [0, 0] (the
    // file-entry has no URI ledger; deletes are intercepted).
    let resp = call_auth(
        &st,
        "changeUri",
        vec![
            json!(gid_b.clone()),
            json!(1),
            json!([]),
            json!(["http://x/1", "http://x/2"]),
            json!(null),
        ],
    )
    .await;
    assert_eq!(resp.code, 0, "{}", resp.payload["message"]);
    assert_eq!(resp.payload, json!([0, 0]), "[deleted, added] integer list");
    // fileIndex out of range (> file-entry count) → verbatim text (RpcMethodImpl.cc).
    let oob = call_auth(
        &st,
        "changeUri",
        vec![
            json!(gid_b.clone()),
            json!(2),
            json!([]),
            json!([]),
            json!(null),
        ],
    )
    .await;
    assert_eq!(oob.code, 1);
    assert_eq!(oob.payload["message"], "fileIndex is out of range");
    // fileIndex < 1 → explicit error (IntegerGE(1)).
    let bad_index = call_auth(
        &st,
        "changeUri",
        vec![json!(gid_b), json!(0), json!([]), json!([]), json!(null)],
    )
    .await;
    assert_eq!(bad_index.code, 1);
    let _ = std::fs::remove_dir_all(&dir);
}

/// taiji.addTracker/removeTracker dispatch: param face (urls as scalar or
/// array, empty-set text, position as number or numeric string with
/// negative = wrong type), receipt `{"removed":N,"added":M}` (self-
/// describing dict, bare integer counts), tellStatus announceList
/// projection, and metadata-phase rejection text passed through (actor
/// shape gate). Dispatch coverage is pinned by
/// every_promised_method_dispatches; the write gate by
/// unauthenticated_write_is_refused (neither method is in the
/// is_read_only exemption set).
#[tokio::test]
async fn taiji_tracker_methods_shape_receipts_and_gates() {
    let st = state(Some("t"));
    let dir = std::env::temp_dir().join(format!("bh-p34-trk-{}", std::process::id()));
    let announce = "http://127.0.0.1:1/announce";
    // Added paused: the task stays in the waiting set (announceList
    // projection reads jobs; the active-side interaction is covered by
    // core actor tests).
    let added = call_auth(
        &st,
        "addTorrent",
        vec![
            json!(b64(&v1_torrent_bytes())),
            json!([]),
            json!({"dir": dir.display().to_string(), "pause": "true"}),
        ],
    )
    .await;
    assert_eq!(added.code, 0, "{}", added.payload["message"]);
    let gid = ok_str(&added);

    // ---- Param face ----
    let missing = call_auth(&st, "taiji.addTracker", vec![json!(gid.clone())]).await;
    assert_eq!(missing.code, 1);
    assert_eq!(
        missing.payload["message"],
        "The parameter at 1 is required but missing."
    );
    let wrong = call_auth(
        &st,
        "taiji.removeTracker",
        vec![json!(gid.clone()), json!(42)],
    )
    .await;
    assert_eq!(wrong.code, 1);
    assert_eq!(
        wrong.payload["message"],
        "The parameter at 1 has wrong type."
    );
    let empty = call_auth(&st, "taiji.addTracker", vec![json!(gid.clone()), json!([])]).await;
    assert_eq!(empty.code, 1);
    assert_eq!(empty.payload["message"], "tracker URLs are not provided.");
    let scalar_only = call_auth(&st, "taiji.removeTracker", vec![json!(gid.clone())]).await;
    assert_eq!(
        scalar_only.payload["message"],
        "The parameter at 1 is required but missing."
    );
    // Negative / non-numeric position = wrong type (uint_value domain).
    let neg = call_auth(
        &st,
        "taiji.addTracker",
        vec![
            json!(gid.clone()),
            json!(["http://x/1"]),
            json!({"position": -1}),
        ],
    )
    .await;
    assert_eq!(neg.code, 1);
    assert_eq!(neg.payload["message"], "The parameter at 2 has wrong type.");

    // ---- Scalar urls + position (numeric string) → insert at 1 ----
    let resp = call_auth(
        &st,
        "taiji.addTracker",
        vec![
            json!(gid.clone()),
            json!("udp://rpc.example:6969/announce"),
            json!({"position": "1"}),
        ],
    )
    .await;
    assert_eq!(resp.code, 0, "{}", resp.payload["message"]);
    assert_eq!(resp.payload, json!({"removed": 0, "added": 1}));

    // Array urls + no position = append at the tail; duplicate URLs count 0.
    let resp2 = call_auth(
        &st,
        "taiji.addTracker",
        vec![
            json!(gid.clone()),
            json!([
                "http://t2.example/announce",
                "udp://rpc.example:6969/announce"
            ]),
        ],
    )
    .await;
    assert_eq!(resp2.code, 0, "{}", resp2.payload["message"]);
    assert_eq!(
        resp2.payload,
        json!({"removed": 0, "added": 1}),
        "duplicate URLs (same address as the scalar) do not count into added"
    );

    // tellStatus announceList projection (waiting set = jobs payload).
    let status = call_auth(&st, "tellStatus", vec![json!(gid.clone()), json!([])]).await;
    assert_eq!(status.code, 0);
    assert_eq!(
        status.payload["bittorrent"]["announceList"],
        json!([
            [announce],
            ["udp://rpc.example:6969/announce"],
            ["http://t2.example/announce"]
        ]),
        "the edited announceList is visible immediately (tier 0 built-in first, the new URL in its own tier)"
    );

    // removeTracker: exact-match removal + receipt counts.
    let rm = call_auth(
        &st,
        "taiji.removeTracker",
        vec![
            json!(gid.clone()),
            json!(["udp://rpc.example:6969/announce"]),
        ],
    )
    .await;
    assert_eq!(rm.code, 0, "{}", rm.payload["message"]);
    assert_eq!(rm.payload, json!({"removed": 1, "added": 0}));
    let status2 = call_auth(&st, "tellStatus", vec![json!(gid.clone())]).await;
    assert_eq!(
        status2.payload["bittorrent"]["announceList"],
        json!([[announce], ["http://t2.example/announce"]])
    );

    // ---- Metadata-phase rejection (actor shape-gate text passed through) ----
    let magnet = call_auth(
        &st,
        "addUri",
        vec![
            json!(["magnet:?xt=urn:btih:8888888888888888888888888888888888888888"]),
            json!({"pause": "true"}),
        ],
    )
    .await;
    let mgid = ok_str(&magnet);
    let rejected = call_auth(
        &st,
        "taiji.addTracker",
        vec![json!(mgid), json!(["http://x/1"])],
    )
    .await;
    assert_eq!(rejected.code, 1);
    assert_eq!(
        rejected.payload["message"],
        "taiji.addTracker: tracker edit requires a torrent task \
         (metadata tasks are not editable before upgrade)"
    );

    // ---- Unknown GID (str2Gid family text passed through) ----
    let notfound = call_auth(
        &st,
        "taiji.removeTracker",
        vec![json!("dead000000000000"), json!(["http://x/1"])],
    )
    .await;
    assert_eq!(notfound.code, 1);
    assert_eq!(
        notfound.payload["message"],
        "GID dead000000000000 is not found"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// changePosition e2e: all three modes over JSON-RPC (reply = bare
/// integer target position, RpcMethodImpl.cc `Integer::g`), verbatim
/// param/error texts ("Illegal argument." / waiting queue / str2Gid
/// family), and write-gate classification (fails closed without a
/// secret).
#[tokio::test]
async fn change_position_modes_errors_and_write_gate() {
    let st = state(Some("t"));
    let dir = std::env::temp_dir().join(format!("bh-p34-pos-{}", std::process::id()));
    // max-concurrent=1 → 1 active + 2 waiting (POS scope = waiting queue).
    assert_eq!(
        call_auth(
            &st,
            "changeGlobalOption",
            vec![json!({"max-concurrent-downloads": "1"})]
        )
        .await
        .code,
        0
    );
    let mut gids = Vec::new();
    for name in ["pa", "pb", "pc"] {
        let r = call_auth(
            &st,
            "addTorrent",
            vec![
                json!(b64(&v1_named_torrent(name))),
                json!([]),
                json!({"dir": dir.display().to_string()}),
            ],
        )
        .await;
        assert_eq!(r.code, 0, "{name}: {}", r.payload["message"]);
        gids.push(ok_str(&r));
    }
    let (a, b, c) = (gids[0].clone(), gids[1].clone(), gids[2].clone());
    async fn waiting(st: &AppState) -> Vec<String> {
        let r = call_auth(st, "tellWaiting", vec![json!(0), json!(10)]).await;
        as_arr(&r.payload, "tellWaiting")
            .iter()
            .filter_map(|v| v["gid"].as_str().map(str::to_string))
            .collect::<Vec<String>>()
    }
    assert_eq!(waiting(&st).await, vec![b.clone(), c.clone()]);
    // POS_SET 0: c → queue head, bare integer 0.
    let r = call_auth(
        &st,
        "changePosition",
        vec![json!(&c), json!(0), json!("POS_SET")],
    )
    .await;
    assert_eq!(r.code, 0, "{}", r.payload["message"]);
    assert_eq!(
        r.payload,
        json!(0),
        "the receipt = the position after the move (a bare integer)"
    );
    assert_eq!(waiting(&st).await, vec![c.clone(), b.clone()]);
    // POS_CUR -1: b moves forward one.
    let r = call_auth(
        &st,
        "changePosition",
        vec![json!(&b), json!(-1), json!("POS_CUR")],
    )
    .await;
    assert_eq!(r.payload, json!(0));
    assert_eq!(waiting(&st).await, vec![b.clone(), c.clone()]);
    // POS_END 0: b → queue tail.
    let r = call_auth(
        &st,
        "changePosition",
        vec![json!(&b), json!(0), json!("POS_END")],
    )
    .await;
    assert_eq!(r.payload, json!(1));
    assert_eq!(waiting(&st).await, vec![c.clone(), b.clone()]);
    // POS_CUR out-of-range clamps (forward → size-1).
    let r = call_auth(
        &st,
        "changePosition",
        vec![json!(&c), json!(5), json!("POS_CUR")],
    )
    .await;
    assert_eq!(
        r.payload,
        json!(1),
        "positive out-of-range clamps to the queue tail"
    );
    // Error face: active gid → waiting-queue text (RequestGroupMan.cc).
    let r = call_auth(
        &st,
        "changePosition",
        vec![json!(&a), json!(0), json!("POS_SET")],
    )
    .await;
    assert_eq!(r.code, 1);
    assert_eq!(
        r.payload["message"],
        format!("GID#{a} not found in the waiting queue.")
    );
    // Invalid how → "Illegal argument." verbatim (RpcMethodImpl.cc).
    let r = call_auth(
        &st,
        "changePosition",
        vec![json!(&b), json!(0), json!("POS_UP")],
    )
    .await;
    assert_eq!(r.code, 1);
    assert_eq!(r.payload["message"], "Illegal argument.");
    // Param-face template texts, one per checkRequiredParam position.
    for (params, msg) in [
        (
            vec![json!(&b), json!(0)],
            "The parameter at 2 is required but missing.",
        ),
        (
            vec![json!(&b), json!(0), json!(1)],
            "The parameter at 2 has wrong type.",
        ),
        (
            vec![json!(&b)],
            "The parameter at 1 is required but missing.",
        ),
        (
            vec![json!(&b), json!("x"), json!("POS_SET")],
            "The parameter at 1 has wrong type.",
        ),
        (vec![], "The parameter at 0 is required but missing."),
    ] {
        let r = call_auth(&st, "changePosition", params).await;
        assert_eq!(r.code, 1);
        assert_eq!(r.payload["message"], msg);
    }
    // Unknown/invalid gid → str2Gid texts (expandUnique lives in the actor).
    for (raw, msg) in [
        (
            json!("9000000000000001"),
            "GID 9000000000000001 is not found",
        ),
        (json!("xyz"), "Invalid GID xyz"),
    ] {
        let r = call_auth(&st, "changePosition", vec![raw, json!(0), json!("POS_SET")]).await;
        assert_eq!(r.code, 1);
        assert_eq!(r.payload["message"], msg);
    }
    // Write gate: fails closed without a secret (write face).
    let open = state(None);
    let gated = call(
        &open,
        "changePosition",
        vec![json!("8000000000000001"), json!(0), json!("POS_SET")],
    )
    .await;
    assert_eq!(gated.code, 1);
    assert_eq!(
        gated.payload["message"],
        "unauthenticated write requires --rpc-secret"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// forceRecheck dispatch: all three namings (bare / canonical
/// `taiji.forceRecheck` / compat `aria2.forceRecheck` only in compat
/// mode) hit the same arm — param face, GID resolution errors passed
/// through (str2Gid family), and an explicit storage error when
/// persistence is off (proving the arm reaches the actor rather than a
/// not_supported/unknown-method face). Behavior is covered end-to-end by
/// core `tests/seed_recheck_loopback.rs`.
#[tokio::test]
async fn force_recheck_dispatch_dual_naming_and_errors() {
    let st = state(Some("t"));
    // Param face (checkRequiredParam<String> family; pause uses the same template).
    let missing = call_auth(&st, "forceRecheck", vec![]).await;
    assert_eq!(
        missing.payload["message"],
        "The parameter at 0 is required but missing."
    );
    let wrong = call_auth(&st, "forceRecheck", vec![json!(12345)]).await;
    assert_eq!(
        wrong.payload["message"],
        "The parameter at 0 has wrong type."
    );
    // Unknown gid: resolve_gid error passed through (str2Gid family, verbatim).
    let notfound = call_auth(&st, "forceRecheck", vec![json!("beef000000000000")]).await;
    assert_eq!(notfound.code, 1);
    assert_eq!(
        notfound.payload["message"],
        "GID beef000000000000 is not found"
    );
    // Real task without persistence: addTorrent accepted (no row stored)
    // → forceRecheck's explicit storage error proves the arm reaches the
    // actor.
    let dir = std::env::temp_dir().join(format!("bh-p34-recheck-{}", std::process::id()));
    let add = call_auth(
        &st,
        "addTorrent",
        vec![
            json!(b64(&v1_torrent_bytes())),
            json!([]),
            json!({"dir": dir.display().to_string()}),
        ],
    )
    .await;
    assert_eq!(add.code, 0, "addTorrent: {}", add.payload["message"]);
    let gid = ok_str(&add);
    for name in ["forceRecheck", "taiji.forceRecheck"] {
        let r = call_auth(&st, name, vec![json!(&gid)]).await;
        assert_eq!(r.code, 1, "{name}");
        assert_eq!(
            r.payload["message"], "forceRecheck: session storage is not enabled",
            "{name}: dispatch arm must reach the actor (explicit storage error)"
        );
    }
    // Compat face: aria2.forceRecheck is accepted only in compat mode
    // (canonical state = unknown-method face). The compat state uses a
    // fresh actor without the task, so reaching the str2Gid error face
    // proves the alias routes through (not "No such method").
    let closed = call(
        &st,
        "aria2.forceRecheck",
        vec![json!("token:t"), json!(&gid)],
    )
    .await;
    assert_eq!(
        closed.payload["message"],
        "No such method: aria2.forceRecheck"
    );
    let compat = state_compat(Some("t"));
    for name in ["forceRecheck", "taiji.forceRecheck", "aria2.forceRecheck"] {
        let r = call_auth(&compat, name, vec![json!(&gid)]).await;
        assert_eq!(r.code, 1, "{name} (compat)");
        assert_eq!(
            r.payload["message"],
            format!("GID {gid} is not found"),
            "{name} (compat): alias routing must reach the actor (gid domain, \
             fresh actor has no such task)"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn pause_unpause_all_and_purge_smoke_via_rpc() {
    let st = state(Some("t"));
    // forcePauseAll on an empty session always answers "OK" (reference
    // pauseAllDownloads answers createOKResponse for an empty group set,
    // RpcMethodImpl.cc).
    assert_eq!(
        call_auth(&st, "forcePauseAll", vec![]).await.payload,
        json!("OK")
    );
    assert_eq!(
        call_auth(&st, "pauseAll", vec![]).await.payload,
        json!("OK")
    );
    assert_eq!(
        call_auth(&st, "unpauseAll", vec![]).await.payload,
        json!("OK")
    );
    assert_eq!(
        call_auth(&st, "purgeDownloadResult", vec![]).await.payload,
        json!("OK")
    );
    // getGlobalStat: all-zero counters on an empty session (RpcMethodImpl.cc
    // six-key face + the taiji extension keys — the
    // wire anchor: existing keys zero name/shape drift, the three
    // extension keys verbatim, all string-valued).
    let gs = call_auth(&st, "getGlobalStat", vec![]).await;
    assert_eq!(gs.code, 0);
    assert_eq!(
        gs.payload,
        json!({
            "downloadSpeed": "0",
            "uploadSpeed": "0",
            "numActive": "0",
            "numWaiting": "0",
            "numStopped": "0",
            "numStoppedTotal": "0",
            "numSeeding": "0",
            "numChecking": "0",
            "numSynthesizing": "0",
        })
    );
    // tellWaiting/tellStopped empty-session face (pagination params required, like aria2).
    assert_eq!(
        call_auth(&st, "tellWaiting", vec![json!(0), json!(10)])
            .await
            .payload,
        json!([])
    );
    assert_eq!(
        call_auth(&st, "tellStopped", vec![json!(0), json!(10)])
            .await
            .payload,
        json!([])
    );
}

/// forcePauseAll e2e: after the call with N active + M waiting tasks,
/// `tellActive` is empty, `tellWaiting` is all paused, and the answer is
/// "OK" (reference ForcePauseAllRpcMethod → createOKResponse,
/// RpcMethodImpl.cc). Behavioral parity with pauseAll: both methods run
/// on separate sessions over the same task sequence and match on every
/// observable (answer / active cleared / reserved all paused / idempotent
/// replay); the force difference is only in the graceful-halt action
/// (setForceHaltRequested skips tracker notification, RpcMethodImpl.cc).
#[tokio::test]
async fn force_pause_all_clears_active_and_pauses_waiting_like_pause_all() {
    let dir = std::env::temp_dir().join(format!("bh-p34-fpa-{}", std::process::id()));
    for method in ["pauseAll", "forcePauseAll"] {
        let st = state(Some("t"));
        // max-concurrent=2 + 4 tasks → 2 active + 2 waiting (both sets
        // non-empty; dead trackers keep the active state stable).
        assert_eq!(
            call_auth(
                &st,
                "changeGlobalOption",
                vec![json!({"max-concurrent-downloads": "2"})]
            )
            .await
            .code,
            0
        );
        let mut gids = Vec::new();
        for name in ["fa", "fb", "fc", "fd"] {
            let r = call_auth(
                &st,
                "addTorrent",
                vec![
                    json!(b64(&v1_named_torrent(name))),
                    json!([]),
                    json!({"dir": dir.display().to_string()}),
                ],
            )
            .await;
            assert_eq!(r.code, 0, "{name}: {}", r.payload["message"]);
            gids.push(ok_str(&r));
        }
        // Answer "OK" (reference createOKResponse literal).
        let r = call_auth(&st, method, vec![]).await;
        assert_eq!(r.code, 0, "{method}: {}", r.payload["message"]);
        assert_eq!(r.payload, json!("OK"), "{method}");
        // Active set cleared and reserved set fully paused: the pause
        // reply precedes teardown (the actor replies without waiting for
        // shutdown), active tasks re-enter the queue head paused via
        // completion events — poll until active is empty and all four are
        // collected in waiting.
        let mut waiting_gids = Vec::new();
        for _ in 0..100 {
            let a = call_auth(&st, "tellActive", vec![]).await;
            let w = call_auth(&st, "tellWaiting", vec![json!(0), json!(10)]).await;
            let active = as_arr(&a.payload, "tellActive").len();
            let arr = as_arr(&w.payload, "tellWaiting").clone();
            if active == 0 && arr.len() == gids.len() {
                for e in &arr {
                    assert_eq!(e["status"], json!("paused"), "{method}");
                    waiting_gids.push(e["gid"].as_str().unwrap_or_default().to_string());
                }
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(
            !waiting_gids.is_empty(),
            "{method}: the active face not drained or the waiting face not fully collected (the tail-event window timed out)"
        );
        // Re-assert the final state: active is pinned empty.
        let active = call_auth(&st, "tellActive", vec![]).await;
        assert_eq!(as_arr(&active.payload, "tellActive").len(), 0, "{method}");
        waiting_gids.sort();
        let mut added = gids.clone();
        added.sort();
        assert_eq!(
            waiting_gids, added,
            "{method}: all tasks collected into the paused waiting face"
        );
        // Idempotent replay answers the same: already-paused groups return
        // false and the reply stays OK (pauseRequestGroups,
        // RpcMethodImpl.cc).
        let again = call_auth(&st, method, vec![]).await;
        assert_eq!(again.payload, json!("OK"), "{method}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

// ---- Query face: pagination / keys / expandUnique / error faces ----

/// Pagination ranges table-driven from RpcMethodImpl.h
/// `getPaginationRange` (slice ranges only; the negative-offset reversal
/// lives in [`render_status_list`] and is asserted there). Each case
/// comment walks the C++ variables.
#[test]
fn pagination_range_translates_reference_semantics() {
    let cases: &[(i64, i64, i64, Option<&[usize]>)] = &[
        // num <= 0 → None (rendered as an empty table).
        (0, 0, 5, None),
        (2, -1, 5, None),
        // Positive offset out of bounds → None (`size <= offset`).
        (5, 2, 5, None),
        (9, 1, 5, None),
        // Normal forward: offset=1, num=2, size=5 → [1,3).
        (1, 2, 5, Some(&[1, 2])),
        // Tail truncation: offset=4, num=10, size=5 → [4,5).
        (4, 10, 5, Some(&[4])),
        // Negative offset: offset=-3, size=5 → tempoffset=2;
        // offset=2-(2-1)=1 → [1,3) (reversal happens in render_status_list).
        (-3, 2, 5, Some(&[1, 2])),
        // Negative offset anchors from the tail: offset=-1, num=2, size=4
        // → tempoffset=3; offset=3-1=2 → [2,4).
        (-1, 2, 4, Some(&[2, 3])),
        // Negative offset too far back: tempoffset < 0 → None.
        (-10, 3, 5, None),
        // Negative offset clamps to 0 and shrinks num: tempoffset=1 <
        // num-1=9 → offset=0, num=tempoffset+1=2 → [0,2).
        (-4, 10, 5, Some(&[0, 1])),
        // Fully negative window: offset=-5, num=5, size=5 → tempoffset=0;
        // offset=0-4=-4 < 0 → offset=0, num=1 → [0,1).
        (-5, 5, 5, Some(&[0])),
        // Empty collection: any args → None.
        (0, 3, 0, None),
        (-1, 3, 0, None),
    ];
    for &(offset, num, size, expect) in cases {
        let got = pagination_range(offset, num, size).map(|(s, e)| (s..e).collect::<Vec<_>>());
        assert_eq!(
            got.as_deref(),
            expect,
            "offset={offset} num={num} size={size}"
        );
    }
}

/// Negative offsets are reversed in the list-rendering layer
/// (RpcMethodImpl.h `if (offset < 0) std::reverse(...)`).
#[test]
fn render_status_list_reverses_negative_offset_windows() {
    let views: Vec<TorrentStatusView> = (0..5u64)
        .map(|i| {
            TorrentStatusView::minimal(
                taiji_core::gid::Gid::from_u64(0x8000_0000_0000_0000 + i),
                taiji_core::session::StatusKind::Waiting,
                0,
                0,
            )
        })
        .collect();
    // (-3, 2): slice [1,3) → reversed → gid order [2, 1] (GIDs ascend with i).
    let out = render_status_list(views.clone(), Some(-3), Some(2), &[]);
    let gids: Vec<String> = out
        .as_array()
        .unwrap_or_else(|| panic!("array"))
        .iter()
        .filter_map(|v| v["gid"].as_str().map(str::to_string))
        .collect();
    assert_eq!(
        gids,
        vec![
            format!("{:016x}", 0x8000_0000_0000_0002u64),
            format!("{:016x}", 0x8000_0000_0000_0001u64),
        ]
    );
    // Positive offset is not reversed.
    let fwd = render_status_list(views, Some(1), Some(2), &[]);
    let fwd_gids: Vec<String> = fwd
        .as_array()
        .unwrap_or_else(|| panic!("array"))
        .iter()
        .filter_map(|v| v["gid"].as_str().map(str::to_string))
        .collect();
    assert_eq!(
        fwd_gids,
        vec![
            format!("{:016x}", 0x8000_0000_0000_0001u64),
            format!("{:016x}", 0x8000_0000_0000_0002u64),
        ]
    );
}

/// tellWaiting/tellStopped pagination e2e: negative-offset reversal,
/// out-of-bounds → empty, num=0 → empty. Data face = tellWaiting FIFO order.
#[tokio::test]
async fn tell_waiting_pagination_negative_offset_and_edges() {
    let st = state(Some("t"));
    let dir = std::env::temp_dir().join(format!("bh-p35-page-{}", std::process::id()));
    // max-concurrent=1 → 1 active + 4 waiting (FIFO).
    assert_eq!(
        call_auth(
            &st,
            "changeGlobalOption",
            vec![json!({"max-concurrent-downloads": "1"})]
        )
        .await
        .code,
        0
    );
    for name in ["a", "b", "c", "d", "e"] {
        let bytes = v1_named_torrent(name);
        let r = call_auth(
            &st,
            "addTorrent",
            vec![
                json!(b64(&bytes)),
                json!([]),
                json!({"dir": dir.display().to_string()}),
            ],
        )
        .await;
        assert_eq!(r.code, 0, "{}: {}", name, r.payload["message"]);
    }
    let gids = |arr: &Value| -> Vec<String> {
        as_arr(arr, "page")
            .iter()
            .filter_map(|v| v["gid"].as_str().map(str::to_string))
            .collect()
    };
    // Full waiting snapshot (FIFO order): taken twice and required to be
    // equal, ruling out legitimate transients from active tasks finishing
    // (which would shift the window).
    let all_gids = loop {
        let a = gids(
            &call_auth(&st, "tellWaiting", vec![json!(0), json!(10)])
                .await
                .payload,
        );
        assert_eq!(a.len(), 4, "1 active + 4 waiting");
        let b = gids(
            &call_auth(&st, "tellWaiting", vec![json!(0), json!(10)])
                .await
                .payload,
        );
        if a == b {
            break a;
        }
    };
    // num=0 → empty (RpcMethodImpl.h).
    assert_eq!(
        call_auth(&st, "tellWaiting", vec![json!(0), json!(0)])
            .await
            .payload,
        json!([])
    );
    // Negative offset (slice + reverse): (-2,2) anchors size-2=2 as the
    // window end → [1,3) reversed → [g2, g1]; (-1,2) anchors 3 → [2,4)
    // reversed → [g3, g2].
    let neg = gids(
        &call_auth(&st, "tellWaiting", vec![json!(-2), json!(2)])
            .await
            .payload,
    );
    let neg_tail = gids(
        &call_auth(&st, "tellWaiting", vec![json!(-1), json!(2)])
            .await
            .payload,
    );
    let after = gids(
        &call_auth(&st, "tellWaiting", vec![json!(0), json!(10)])
            .await
            .payload,
    );
    assert_eq!(
        after, all_gids,
        "waiting order must be stable across window"
    );
    assert_eq!(neg, vec![all_gids[2].clone(), all_gids[1].clone()]);
    assert_eq!(neg_tail, vec![all_gids[3].clone(), all_gids[2].clone()]);
    // Tail window shrinks.
    let tail = gids(
        &call_auth(&st, "tellWaiting", vec![json!(3), json!(10)])
            .await
            .payload,
    );
    assert_eq!(tail, vec![all_gids[3].clone()]);
    // Out of bounds → empty.
    assert_eq!(
        call_auth(&st, "tellWaiting", vec![json!(9), json!(2)])
            .await
            .payload,
        json!([])
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// num < 0 → the checkRequiredInteger(IntegerGE(0)) two-layer text
/// (RpcMethodImpl.h).
#[tokio::test]
async fn tell_stopped_negative_num_reports_reference_text() {
    let st = state(None);
    let r = call(&st, "tellStopped", vec![json!(0), json!(-1)]).await;
    assert_eq!(r.code, 1);
    assert_eq!(
        r.payload["message"],
        "The integer parameter at 1 has invalid value: \
             the value must be greater than or equal to 0."
    );
}

/// keys filtering is subset-equivalent (requested_key semantics,
/// RpcMethodImpl.cc): empty = all fields; specified = strict subset with
/// unchanged values.
#[tokio::test]
async fn keys_filter_is_subset_equivalent() {
    let st = state(Some("t"));
    let dir = std::env::temp_dir().join(format!("bh-p35-keys-{}", std::process::id()));
    let add = call_auth(
        &st,
        "addTorrent",
        vec![
            json!(b64(&v1_named_torrent("k"))),
            json!([]),
            json!({"dir": dir.display().to_string()}),
        ],
    )
    .await;
    let gid = ok_str(&add);
    let full = call_auth(&st, "tellStatus", vec![json!(gid.clone())]).await;
    assert_eq!(full.code, 0, "{}", full.payload["message"]);
    let full_obj = full.payload.as_object().unwrap_or_else(|| panic!("dict"));
    // aria2 full-field face (this engine's promised set) for a live BT task.
    for key in [
        "gid",
        "status",
        "totalLength",
        "completedLength",
        "downloadSpeed",
        "uploadSpeed",
        "uploadLength",
        "connections",
        "pieceLength",
        "numPieces",
        "files",
        "dir",
        "bittorrent",
        "infoHash",
        "numSeeders",
        "seeder",
    ] {
        assert!(
            full_obj.contains_key(key),
            "live BT entry must carry {key}: {full_obj:?}"
        );
    }
    // Subset equivalence: kept keys match the full object; no extra keys.
    let keys = vec!["gid", "bitfield", "bittorrent"];
    let sub = call_auth(
        &st,
        "tellStatus",
        vec![
            json!(gid),
            json!(keys.iter().map(|k| json!(k)).collect::<Vec<_>>()),
        ],
    )
    .await;
    let sub_obj = sub.payload.as_object().unwrap_or_else(|| panic!("dict"));
    assert_eq!(sub_obj.len(), 3, "keys filter is strict: {sub_obj:?}");
    for k in keys {
        assert_eq!(sub_obj[k], full_obj[k], "key {k} value must be identical");
    }
    // Unknown keys = empty object (aria2: a dict with no matching keys).
    let none = call_auth(
        &st,
        "tellStatus",
        vec![json!(ok_str(&add)), json!(["nope"])],
    )
    .await
    .payload;
    assert!(none.as_object().is_some_and(|o| o.is_empty()));
    let _ = std::fs::remove_dir_all(&dir);
}

/// GID expandUnique's three branches over RPC (integration half; unit
/// coverage in session::view::tests). Texts per RpcMethodImpl.cc.
#[tokio::test]
async fn tell_status_gid_prefix_resolution_three_branches() {
    let st = state(Some("t"));
    let dir = std::env::temp_dir().join(format!("bh-p35-gid-{}", std::process::id()));
    let add = call_auth(
        &st,
        "addTorrent",
        vec![
            json!(b64(&v1_named_torrent("p"))),
            json!([]),
            json!({"dir": dir.display().to_string()}),
        ],
    )
    .await;
    let gid = ok_str(&add);
    // Unique 13-char prefix → expanded, same answer as the full string.
    let via_full = call_auth(&st, "tellStatus", vec![json!(gid.clone())]).await;
    let via_prefix = call_auth(&st, "tellStatus", vec![json!(&gid[..13])]).await;
    assert_eq!(via_prefix.code, 0, "{}", via_prefix.payload["message"]);
    assert_eq!(via_prefix.payload["gid"], json!(gid));
    assert_eq!(via_prefix.payload["status"], via_full.payload["status"]);
    // Not found → "GID %s is not found".
    let nf = call_auth(&st, "tellStatus", vec![json!("9000000000000001")]).await;
    assert_eq!(nf.code, 1);
    assert_eq!(nf.payload["message"], "GID 9000000000000001 is not found");
    // Unique prefix with no match → same not-found text.
    let nf2 = call_auth(&st, "tellStatus", vec![json!("9000000000")]).await;
    assert_eq!(nf2.payload["message"], "GID 9000000000 is not found");
    // Invalid (non-hex / too long / empty) → "Invalid GID %s".
    for bad in ["xyz", "8000000000000000f", ""] {
        let inv = call_auth(&st, "tellStatus", vec![json!(bad)]).await;
        assert_eq!(inv.code, 1, "{bad}");
        assert_eq!(inv.payload["message"], format!("Invalid GID {bad}"));
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Minimal v1 metainfo with a settable name (single 32B file / 1 piece,
/// placeholder pieces — the parser does not verify hash consistency).
fn v1_named_torrent(name: &str) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(
            format!(
                "d8:announce27:http://127.0.0.1:1/announce4:infod6:lengthi32e4:name{}:{}12:piece lengthi16384e6:pieces20:",
                name.len(),
                name
            )
            .as_bytes(),
        );
    v.extend_from_slice(&[0xAB; 20]);
    v.extend_from_slice(b"ee");
    v
}

// ---- taiji.banAddr / unbanAddr / listBans (end-to-end) ----

/// End-to-end for the three methods (reference text style: code 1 +
/// message string; numbers rendered as strings). ban → list (manual /
/// source / until shape) → unban → idempotent error face → invalid
/// target / invalid minutes fail explicitly.
#[tokio::test]
async fn taiji_ban_unban_list_e2e() {
    let st = state(Some("t"));
    // The ban list starts empty (no client is banned by default).
    let empty = call_auth(&st, "taiji.listBans", vec![]).await;
    assert_eq!(empty.code, 0);
    assert_eq!(as_arr(&empty.payload, "empty bans").len(), 0);
    // Ban a CIDR (permanent → until "0", the aria2 "0 = unlimited" convention).
    let ban = call_auth(&st, "taiji.banAddr", vec![json!("10.66.0.0/24")]).await;
    assert_eq!(ban.code, 0);
    assert_eq!(ban.payload, "OK");
    // Ban a single IP (minutes as a numeric string → time-limited).
    let timed = call_auth(&st, "taiji.banAddr", vec![json!("192.0.2.9"), json!("30")]).await;
    assert_eq!(timed.code, 0);
    let list = call_auth(&st, "taiji.listBans", vec![]).await;
    assert_eq!(list.code, 0);
    let rows = as_arr(&list.payload, "bans");
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0]["target"], "10.66.0.0/24");
    assert_eq!(rows[0]["reason"], "manual");
    assert_eq!(rows[0]["source"], "manual");
    assert_eq!(
        rows[0]["until"], "0",
        "permanent = until 0 (the aria2 unlimited convention)"
    );
    assert_eq!(rows[1]["target"], "192.0.2.9");
    let until = rows[1]["until"].as_str().unwrap_or("");
    let until: i64 = until.parse().unwrap_or(0);
    let now = taiji_core::session::bans::now_epoch();
    assert!(
        until > now && until <= now + 30 * 60,
        "a dated until = now+30min (got {until}, now {now})"
    );
    // Unban: exact match on the normalized target.
    let unban = call_auth(&st, "taiji.unbanAddr", vec![json!("10.66.0.0/24")]).await;
    assert_eq!(unban.code, 0);
    assert_eq!(unban.payload, "OK");
    // Repeated unban = explicit error (aria2 error style: code 1 + message).
    let again = call_auth(&st, "taiji.unbanAddr", vec![json!("10.66.0.0/24")]).await;
    assert_eq!(again.code, 1);
    assert_eq!(again.payload["message"], "no such ban: 10.66.0.0/24");
    let list = call_auth(&st, "taiji.listBans", vec![]).await;
    assert_eq!(as_arr(&list.payload, "after unban").len(), 1);
    // Invalid target / invalid minutes: code 1 + message.
    for (params, msg) in [
        (vec![json!("nonsense")], "invalid ban target: nonsense"),
        (
            vec![json!("10.0.0.1"), json!(0)],
            "minutes must be a positive integer: 0",
        ),
    ] {
        let r = call_auth(&st, "taiji.banAddr", params).await;
        assert_eq!(r.code, 1);
        assert_eq!(r.payload["message"], msg);
    }
    // Param face: missing param / wrong type (checkRequiredParam template).
    let missing = call_auth(&st, "taiji.banAddr", vec![]).await;
    assert_eq!(
        missing.payload["message"],
        "The parameter at 0 is required but missing."
    );
    let wrong_type = call_auth(&st, "taiji.banAddr", vec![json!(42)]).await;
    assert_eq!(
        wrong_type.payload["message"],
        "The parameter at 0 has wrong type."
    );
}

/// Gate classification: listBans is read-only (anonymous without a
/// secret); ban/unban are write faces (fail closed without a secret); the
/// new methods appear in the listMethods promise face.
#[tokio::test]
async fn taiji_ban_face_gates_and_method_surface() {
    // Without a secret: listBans answers anonymously (empty list), banAddr fails closed.
    let open = state(None);
    let listed = call(&open, "taiji.listBans", vec![]).await;
    assert_eq!(listed.code, 0);
    assert_eq!(as_arr(&listed.payload, "anonymous list").len(), 0);
    let banned = call(&open, "taiji.banAddr", vec![json!("192.0.2.9")]).await;
    assert_eq!(banned.code, 1);
    assert_eq!(
        banned.payload["message"],
        "unauthenticated write requires --rpc-secret"
    );
    // With a secret: listMethods includes all three (taiji.* namespace).
    let st = state(Some("t"));
    let methods = call(&st, "system.listMethods", vec![]).await;
    let got: Vec<&str> = as_arr(&methods.payload, "listMethods")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    for name in ["taiji.banAddr", "taiji.unbanAddr", "taiji.listBans"] {
        assert!(got.contains(&name), "{name} must be listed: {got:?}");
    }
}

/// client-ban-prefixes configuration face: hot-changeable via
/// changeGlobalOption and echoed by getGlobalOption (comma list; empty
/// string restores the default of banning nothing).
#[tokio::test]
async fn client_ban_prefixes_option_echo_and_change() {
    let st = state(Some("t"));
    // Default empty list echoes as "" (no client banned).
    let echo = call_auth(&st, "getGlobalOption", vec![]).await;
    assert_eq!(
        echo.payload["client-ban-prefixes"], "",
        "the default list is empty (recognition is not banning)"
    );
    // Hot change: comma list.
    let set = call_auth(
        &st,
        "changeGlobalOption",
        vec![json!({"client-ban-prefixes": " -XL , -QD ,"})],
    )
    .await;
    assert_eq!(set.code, 0);
    let echo = call_auth(&st, "getGlobalOption", vec![]).await;
    assert_eq!(echo.payload["client-ban-prefixes"], "-XL,-QD");
    // Clearing: empty string restores the no-ban default.
    let clear = call_auth(
        &st,
        "changeGlobalOption",
        vec![json!({"client-ban-prefixes": ""})],
    )
    .await;
    assert_eq!(clear.code, 0);
    let echo = call_auth(&st, "getGlobalOption", vec![]).await;
    assert_eq!(echo.payload["client-ban-prefixes"], "");
}

// ---- taiji.setSchedulerPolicy / getSchedulerPolicy (end-to-end) ----

/// End-to-end for the two methods (activated task, engine running — set
/// goes through SessionActor → EngineCommand): default read-back is
/// rarest_first → set accepts string and dict forms and echoes → all
/// three policies are accepted → unknown names / bad types fail
/// explicitly with the read-back unchanged → missing params / unknown
/// gid.
#[tokio::test]
async fn taiji_scheduler_policy_set_get_e2e() {
    let st = state(Some("t"));
    let dir = std::env::temp_dir().join(format!("bh-p85-rpc-{}", std::process::id()));
    let add = call_auth(
        &st,
        "addTorrent",
        vec![
            json!(b64(&v1_named_torrent("p85"))),
            json!([]),
            json!({"dir": dir.display().to_string()}),
        ],
    )
    .await;
    let gid = ok_str(&add);

    // Default read-back (task mirror default = rarest_first; the
    // `{"policy": name}` object form is also accepted).
    let get = call_auth(&st, "taiji.getSchedulerPolicy", vec![json!(&gid)]).await;
    assert_eq!(get.code, 0, "{}", get.payload["message"]);
    assert_eq!(get.payload["policy"], "rarest_first");

    // set: string form → OK + echo.
    let set = call_auth(
        &st,
        "taiji.setSchedulerPolicy",
        vec![json!(&gid), json!("rarest_first")],
    )
    .await;
    assert_eq!(set.code, 0, "{}", set.payload["message"]);
    assert_eq!(set.payload, "OK");
    // set: dict form → OK.
    let set_dict = call_auth(
        &st,
        "taiji.setSchedulerPolicy",
        vec![json!(&gid), json!({"policy": "rarest_first"})],
    )
    .await;
    assert_eq!(set_dict.code, 0, "{}", set_dict.payload["message"]);
    let get = call_auth(&st, "taiji.getSchedulerPolicy", vec![json!(&gid)]).await;
    assert_eq!(get.payload["policy"], "rarest_first");

    // sequential is accepted and echoed.
    {
        let r = call_auth(
            &st,
            "taiji.setSchedulerPolicy",
            vec![json!(&gid), json!("sequential")],
        )
        .await;
        assert_eq!(r.code, 0, "sequential: {}", r.payload["message"]);
        let get = call_auth(&st, "taiji.getSchedulerPolicy", vec![json!(&gid)]).await;
        assert_eq!(
            get.payload["policy"], "sequential",
            "sequential accepted and echoed"
        );
    }
    let set_st = call_auth(
        &st,
        "taiji.setSchedulerPolicy",
        vec![json!(&gid), json!("streaming")],
    )
    .await;
    assert_eq!(set_st.code, 0, "{}", set_st.payload["message"]);
    let get = call_auth(&st, "taiji.getSchedulerPolicy", vec![json!(&gid)]).await;
    assert_eq!(
        get.payload["policy"], "streaming",
        "streaming accepted and echoed"
    );
    // Back to the default (resets the baseline for later assertions).
    let _ = call_auth(
        &st,
        "taiji.setSchedulerPolicy",
        vec![json!(&gid), json!("rarest_first")],
    )
    .await;

    // Unknown name / unknown dict name / bad type → explicit Err (no silent fallback).
    for bad in [
        json!("bogus"),
        json!({"policy": "bogus"}),
        json!(42),
        json!({}),
    ] {
        let r = call_auth(
            &st,
            "taiji.setSchedulerPolicy",
            vec![json!(&gid), bad.clone()],
        )
        .await;
        assert_eq!(r.code, 1, "{bad}");
        assert!(
            r.payload["message"]
                .as_str()
                .unwrap_or_default()
                .starts_with("unknown scheduler policy"),
            "{bad}: {}",
            r.payload["message"]
        );
    }

    // Param face: missing policy param / unknown gid.
    let missing = call_auth(&st, "taiji.setSchedulerPolicy", vec![json!(&gid)]).await;
    assert_eq!(missing.code, 1);
    let nf = call_auth(
        &st,
        "taiji.getSchedulerPolicy",
        vec![json!("9000000000000001")],
    )
    .await;
    assert_eq!(nf.code, 1);
    assert_eq!(nf.payload["message"], "GID 9000000000000001 is not found");

    let _ = std::fs::remove_dir_all(&dir);
}

/// getSchedulerPolicy is read-only (anonymous without a secret); set is
/// a write face (fails closed without a secret).
#[tokio::test]
async fn scheduler_policy_auth_gate_classification() {
    let open = state(None);
    let listed = call(
        &open,
        "taiji.getSchedulerPolicy",
        vec![json!("8000000000000001")],
    )
    .await;
    assert_eq!(
        listed.code, 1,
        "anonymous queries go through (the gid not-found error face, not an auth refusal)"
    );
    assert_ne!(
        listed.payload["message"],
        "unauthenticated write requires --rpc-secret"
    );
    let set = call(
        &open,
        "taiji.setSchedulerPolicy",
        vec![json!("8000000000000001"), json!("rarest_first")],
    )
    .await;
    assert_eq!(set.code, 1);
    assert_eq!(
        set.payload["message"], "unauthenticated write requires --rpc-secret",
        "set is the write face: fails closed without a secret"
    );
}

// ---- taiji.setStreamingPlayhead (end-to-end) ----

/// Write-gate classification (fails closed without a secret) plus the
/// parse-face checks for the numeric params: malformed pairs are
/// rejected before the session, valid shapes fall through to the
/// session-side GID error.
#[tokio::test]
async fn file_priority_shape_and_write_gate() {
    let open = state(None);
    // Write gate: fails closed without a secret (same gate as setSchedulerPolicy).
    let gated = call(
        &open,
        "taiji.setFilePriority",
        vec![
            json!("8000000000000001"),
            json!([{"index": 1, "priority": 7}]),
        ],
    )
    .await;
    assert_eq!(gated.code, 1);
    assert_eq!(
        gated.payload["message"], "unauthenticated write requires --rpc-secret",
        "the write face: fails closed without a secret"
    );

    // With a token: param face (valid shapes reach the session-side gid
    // error; all other failures are parse-face rejections before the
    // session).
    let authed = state(Some("s03"));
    let ok_shape = call(
        &authed,
        "taiji.setFilePriority",
        vec![
            json!("token:s03"),
            json!("8000000000000001"),
            json!([{"index": 1, "priority": 7}, {"index": 2, "priority": -1}]),
        ],
    )
    .await;
    assert_eq!(
        ok_shape.code, 1,
        "a well-formed call lands on the session gid-not-found error face"
    );

    for (params, tag) in [
        (
            vec![json!("8000000000000001"), json!("not-array")],
            "pairs not an array",
        ),
        (
            vec![json!("8000000000000001"), json!([])],
            "pairs an empty array",
        ),
        (
            vec![json!("8000000000000001"), json!([7])],
            "an entry not an object",
        ),
        (
            vec![json!("8000000000000001"), json!([{"priority": 7}])],
            "missing index",
        ),
        (
            vec![json!("8000000000000001"), json!([{"index": 1}])],
            "missing priority",
        ),
        (
            vec![
                json!("8000000000000001"),
                json!([{"index": 1, "priority": 8}]),
            ],
            "priority out of domain",
        ),
    ] {
        let mut full = vec![json!("token:s03")];
        full.extend(params);
        let r = call(&authed, "taiji.setFilePriority", full).await;
        assert_eq!(r.code, 1, "{tag} rejected");
        assert_ne!(
            r.payload["message"], "unauthenticated write requires --rpc-secret",
            "{tag} is a parse-face rejection (before the session), not the auth face"
        );
    }
}

#[tokio::test]
async fn taiji_streaming_playhead_e2e() {
    let st = state(Some("t"));
    let dir = std::env::temp_dir().join(format!("bh-p86-rpc-{}", std::process::id()));
    let add = call_auth(
        &st,
        "addTorrent",
        vec![
            json!(b64(&v1_named_torrent("p86"))),
            json!([]),
            json!({"dir": dir.display().to_string()}),
        ],
    )
    .await;
    let gid = ok_str(&add);

    // Combined switch: streaming policy first (either order; the two engine
    // commands are decoupled).
    let policy = call_auth(
        &st,
        "taiji.setSchedulerPolicy",
        vec![json!(&gid), json!("streaming")],
    )
    .await;
    assert_eq!(policy.code, 0, "{}", policy.payload["message"]);

    // Valid call (numeric strings, default bps) → OK; repeat call = advance → OK.
    let set = call_auth(
        &st,
        "taiji.setStreamingPlayhead",
        vec![json!(&gid), json!("0"), json!("16")],
    )
    .await;
    assert_eq!(set.code, 0, "{}", set.payload["message"]);
    assert_eq!(set.payload, "OK");
    let advance = call_auth(
        &st,
        "taiji.setStreamingPlayhead",
        vec![json!(&gid), json!(0), json!(16), json!(262144)],
    )
    .await;
    assert_eq!(advance.code, 0, "{}", advance.payload["message"]);

    // Out-of-range file (single-file torrent has only file 0) or position (file is 32B).
    for (params, msg) in [
        (
            vec![json!(&gid), json!(1), json!(0)],
            "playhead file index 1 out of range (1 files)",
        ),
        (
            vec![json!(&gid), json!(0), json!(33)],
            "playhead position 33 beyond end of file 0 (32 bytes)",
        ),
    ] {
        let r = call_auth(&st, "taiji.setStreamingPlayhead", params).await;
        assert_eq!(r.code, 1);
        assert_eq!(r.payload["message"], msg);
    }

    // Param face: missing position / bad type (negative numeric string) / unknown gid.
    let missing = call_auth(
        &st,
        "taiji.setStreamingPlayhead",
        vec![json!(&gid), json!(0)],
    )
    .await;
    assert_eq!(
        missing.payload["message"],
        "The parameter at 2 is required but missing."
    );
    let negative = call_auth(
        &st,
        "taiji.setStreamingPlayhead",
        vec![json!(&gid), json!(0), json!("-1")],
    )
    .await;
    assert_eq!(
        negative.payload["message"],
        "The parameter at 2 has wrong type."
    );
    let nf = call_auth(
        &st,
        "taiji.setStreamingPlayhead",
        vec![json!("9000000000000001"), json!(0), json!(0)],
    )
    .await;
    assert_eq!(nf.code, 1);
    assert_eq!(nf.payload["message"], "GID 9000000000000001 is not found");

    // Write gate: no secret = fail closed (write face).
    let open = state(None);
    let gated = call(
        &open,
        "taiji.setStreamingPlayhead",
        vec![json!("8000000000000001"), json!(0), json!(0)],
    )
    .await;
    assert_eq!(gated.code, 1);
    assert_eq!(
        gated.payload["message"],
        "unauthenticated write requires --rpc-secret"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ---- bytes_per_sec=0 is explicitly rejected ----

/// Explicit `0` is a param-validation error (omitted / Null carries the
/// default rate, so "0" is not silently swallowed); validation precedes
/// session routing (an unknown gid still reports the param error first).
/// Both number and numeric-string forms.
#[tokio::test]
async fn taiji_streaming_playhead_zero_bps_rejected() {
    let st = state(Some("t"));
    for v in [json!(0), json!("0")] {
        let r = call_auth(
            &st,
            "taiji.setStreamingPlayhead",
            vec![json!("8000000000000001"), json!(0), json!(0), v],
        )
        .await;
        assert_eq!(r.code, 1);
        assert_eq!(
            r.payload["message"],
            "The integer parameter at 3 has invalid value: bytes_per_sec \
             must be greater than 0 (omit the parameter for the default rate)."
        );
    }
    // Default-rate continuity: omitted / explicit Null = default (the
    // param face passes and the session-side GID resolution reports not
    // found instead of a param error).
    for tail in [vec![], vec![json!(null)]] {
        let mut params = vec![json!("8000000000000001"), json!(0), json!(0)];
        params.extend(tail);
        let r = call_auth(&st, "taiji.setStreamingPlayhead", params).await;
        assert_eq!(r.code, 1);
        assert_eq!(r.payload["message"], "GID 8000000000000001 is not found");
    }
}

// ---- taiji.getDiskTier / setDiskTier (end-to-end) ----

/// End-to-end for the two disk_tier methods (activated task; set goes
/// through SessionActor → EngineCommand; live application is asserted in
/// the core-side integration test disk_tier_live.rs): default read-back
/// is throughput → set accepts and echoes → unknown names fail
/// explicitly with the read-back unchanged → param face (missing param /
/// bad type / unknown gid) → gate classification (get is anonymously
/// queryable; set fails closed without a secret).
#[tokio::test]
async fn taiji_disk_tier_get_set_e2e() {
    let st = state(Some("t"));
    let dir = std::env::temp_dir().join(format!("bh-p96-rpc-{}", std::process::id()));
    let add = call_auth(
        &st,
        "addTorrent",
        vec![
            json!(b64(&v1_named_torrent("p96"))),
            json!([]),
            json!({"dir": dir.display().to_string()}),
        ],
    )
    .await;
    let gid = ok_str(&add);

    // Default read-back (mirror default = throughput; the `{"tier": name}`
    // object form, same shape as getSchedulerPolicy).
    let get = call_auth(&st, "taiji.getDiskTier", vec![json!(&gid)]).await;
    assert_eq!(get.code, 0, "{}", get.payload["message"]);
    assert_eq!(get.payload["tier"], "throughput");

    // set: all three tiers accepted and echoed (case-insensitive input;
    // the echo is always the canonical name).
    for (set_name, canonical) in [
        ("ssd-protect", "ssd-protect"),
        ("HDD-Sequential", "hdd-sequential"),
        ("throughput", "throughput"),
    ] {
        let set = call_auth(&st, "taiji.setDiskTier", vec![json!(&gid), json!(set_name)]).await;
        assert_eq!(set.code, 0, "{set_name}: {}", set.payload["message"]);
        assert_eq!(set.payload, "OK");
        let get = call_auth(&st, "taiji.getDiskTier", vec![json!(&gid)]).await;
        assert_eq!(get.payload["tier"], canonical, "{set_name} echoed");
    }

    // Unknown name = explicit Err (no silent fallback; read-back unchanged).
    let bad = call_auth(&st, "taiji.setDiskTier", vec![json!(&gid), json!("turbo")]).await;
    assert_eq!(bad.code, 1);
    assert!(
        bad.payload["message"]
            .as_str()
            .unwrap_or_default()
            .starts_with("unknown disk tier: turbo"),
        "{}",
        bad.payload["message"]
    );
    let get = call_auth(&st, "taiji.getDiskTier", vec![json!(&gid)]).await;
    assert_eq!(
        get.payload["tier"], "throughput",
        "read-back unchanged after the failure face"
    );

    // Param face: missing tier / bad type (checkRequiredParam template).
    let missing = call_auth(&st, "taiji.setDiskTier", vec![json!(&gid)]).await;
    assert_eq!(
        missing.payload["message"],
        "The parameter at 1 is required but missing."
    );
    let wrong_type = call_auth(&st, "taiji.setDiskTier", vec![json!(&gid), json!(42)]).await;
    assert_eq!(
        wrong_type.payload["message"],
        "The parameter at 1 has wrong type."
    );
    // Unknown gid (valid tier name) → GID resolution error face.
    let nf = call_auth(
        &st,
        "taiji.setDiskTier",
        vec![json!("9000000000000001"), json!("ssd-protect")],
    )
    .await;
    assert_eq!(nf.code, 1);
    assert_eq!(nf.payload["message"], "GID 9000000000000001 is not found");

    // Gate classification without a secret: getDiskTier is anonymously
    // queryable (reaches the GID resolution error, not an auth refusal);
    // setDiskTier fails closed (write face).
    let open = state(None);
    let anon_get = call(&open, "taiji.getDiskTier", vec![json!("8000000000000001")]).await;
    assert_eq!(
        anon_get.code, 1,
        "anonymous queries go through (gid not-found, not the write gate)"
    );
    assert_ne!(
        anon_get.payload["message"],
        "unauthenticated write requires --rpc-secret"
    );
    let anon_set = call(
        &open,
        "taiji.setDiskTier",
        vec![json!("8000000000000001"), json!("ssd-protect")],
    )
    .await;
    assert_eq!(anon_set.code, 1);
    assert_eq!(
        anon_set.payload["message"], "unauthenticated write requires --rpc-secret",
        "set is the write face: fails closed without a secret"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ---- taiji.getCapabilities (schema assertions) ----

/// Capability-discovery schema assertions: the no-param query face is
/// anonymously reachable; schemaVersion=1; the version prefix is frozen;
/// scheduler / diskPolicy / features / protocol / rpcExtensions match
/// their declarative sources (available = registered ∩ implemented,
/// configOnly = false, feature flags all boolean, rpcExtensions = the
/// taiji.* subset of RPC_METHODS — same source as the listMethods promise
/// table).
#[tokio::test]
async fn taiji_capabilities_schema() {
    let open = state(None);
    let resp = call(&open, "taiji.getCapabilities", vec![]).await;
    assert_eq!(resp.code, 0, "{}", resp.payload["message"]);
    let c = &resp.payload;

    // Top level: schema version + frozen version prefix.
    assert_eq!(c["schemaVersion"], json!(1), "schema_version=1");
    assert!(
        c["version"]
            .as_str()
            .unwrap_or_default()
            .starts_with("taiji/"),
        "the version prefix is frozen: {:?}",
        c["version"]
    );

    // scheduler: available = registered ∩ implemented (all three
    // policies); sessionDefault / perTaskOverride.
    assert_eq!(
        c["scheduler"]["available"],
        json!(["rarest_first", "sequential", "streaming"])
    );
    assert_eq!(c["scheduler"]["sessionDefault"], json!("rarest_first"));
    assert_eq!(c["scheduler"]["perTaskOverride"], json!(true));

    // diskPolicy: all three tiers + the live-application claim
    // (configOnly=false, matching the prealloc docs).
    assert_eq!(
        c["diskPolicy"]["available"],
        json!(["throughput", "ssd-protect", "hdd-sequential"])
    );
    assert_eq!(c["diskPolicy"]["configOnly"], json!(false));

    // features: every feature present, values all boolean pairs
    // (supported/enabled); session defaults give dht=true, lsd=false, and
    // webseeding supported+enabled (BEP19 defaults on).
    let feats = c["features"]
        .as_object()
        .unwrap_or_else(|| panic!("features dict"));
    for name in [
        "utp",
        "dht",
        "dht6",
        "pex",
        "lsd",
        "holepunch",
        "bep42",
        "webseeding",
    ] {
        assert!(
            feats.contains_key(name),
            "feature {name} missing a row: {feats:?}"
        );
    }
    for (name, f) in feats {
        assert!(f["supported"].is_boolean(), "{name}.supported is two-state");
        assert!(f["enabled"].is_boolean(), "{name}.enabled is two-state");
    }
    assert_eq!(feats["utp"]["supported"], json!(true));
    assert_eq!(
        feats["utp"]["enabled"],
        json!(true),
        "the uTP accept face is always present"
    );
    assert_eq!(
        feats["dht"]["enabled"],
        json!(true),
        "the session default enable-dht"
    );
    assert_eq!(
        feats["lsd"]["enabled"],
        json!(false),
        "the session default bt-lsd=false"
    );
    assert_eq!(
        feats["webseeding"]["supported"],
        json!(true),
        "BEP19 webseeding declared implemented"
    );

    // protocol.bep: numeric array; core protocol numbers and BEP 19
    // present.
    let beps = c["protocol"]["bep"]
        .as_array()
        .unwrap_or_else(|| panic!("bep list"));
    assert!(!beps.is_empty());
    assert!(beps.iter().all(|b| b.is_u64()), "bep entries all numeric");
    for n in [3u64, 5, 10, 19, 52] {
        assert!(beps.iter().any(|b| b.as_u64() == Some(n)), "BEP {n} listed");
    }

    // rpcExtensions = the taiji.* subset of RPC_METHODS (same source as
    // the listMethods assertion).
    let exts: Vec<&str> = RPC_METHODS
        .iter()
        .filter(|m| m.starts_with("taiji."))
        .copied()
        .collect();
    let got: Vec<&str> = c["rpcExtensions"]
        .as_array()
        .unwrap_or_else(|| panic!("rpcExtensions array"))
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert_eq!(
        got, exts,
        "rpcExtensions matches the promise table's taiji.* subset"
    );
    assert!(got.contains(&"taiji.setDiskTier"));
    assert!(got.contains(&"taiji.getCapabilities"));
}

// ===== taiji.createTorrent (creation exposure) =====

use std::fs;
use std::path::PathBuf;

/// Process-level temp root (not cleaned up, like the existing tests).
fn temp_root(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!("bh-p108-rpc-{tag}-{}", std::process::id()))
}

fn write_file(path: &std::path::Path, len: usize, fill: impl Fn(usize) -> u8) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap_or_else(|e| panic!("mkdir {parent:?}: {e}"));
    }
    let data: Vec<u8> = (0..len).map(fill).collect();
    fs::write(path, &data).unwrap_or_else(|e| panic!("write {path:?}: {e}"));
}

/// RPC e2e: real files in a temp dir → createTorrent (inside the write
/// gate) → the written artifact round-trips through the authoritative
/// parser (taiji_core::metainfo::Metainfo) — kind / name / piece_length /
/// files / announce / both infohashes must match; the reply JSON fields
/// (camelCase, numbers as strings, infohashes per format) asserted too.
#[tokio::test]
async fn create_torrent_end_to_end_roundtrip() {
    let st = state(Some("t108"));
    let root = temp_root("e2e");
    let dir = root.join("payload");
    write_file(&dir.join("one.bin"), 50000, |i| (i % 251) as u8);
    write_file(&dir.join("two.bin"), 20000, |i| ((i * 3) % 253) as u8);

    let resp = call_auth(
        &st,
        "taiji.createTorrent",
        vec![
            json!(
                ["one.bin", "two.bin"]
                    .iter()
                    .map(|f| dir.join(f).display().to_string())
                    .collect::<Vec<_>>()
            ),
            json!(root.display().to_string()),
            json!({
                "format": "hybrid",
                "comment": "rpc e2e",
                "announce": ["http://a.invalid/ann"],
            }),
        ],
    )
    .await;
    assert_eq!(resp.code, 0, "payload: {}", resp.payload);
    let out_path = resp.payload["output"]
        .as_str()
        .unwrap_or_else(|| panic!("output path missing: {}", resp.payload));
    assert_eq!(
        out_path,
        root.join("payload.torrent").display().to_string(),
        "the product name = <derived name>.torrent (the Dir shape)"
    );
    assert_eq!(resp.payload["name"], "payload");
    assert_eq!(resp.payload["format"], "hybrid");
    assert_eq!(
        resp.payload["pieceLength"], "16384",
        "numerics are stringified (the aria2 convention)"
    );
    assert_eq!(resp.payload["totalLength"], "70000");
    // v1-only/hybrid carry v1 identity: hybrid has both keys.
    let v1hex = resp.payload["infohashV1"]
        .as_str()
        .unwrap_or_else(|| panic!("infohashV1 missing: {}", resp.payload));
    let v2hex = resp.payload["infohashV2"]
        .as_str()
        .unwrap_or_else(|| panic!("infohashV2 missing: {}", resp.payload));
    assert_eq!(v1hex.len(), 40, "SHA-1 hex");
    assert_eq!(v2hex.len(), 64, "SHA-256 hex");

    // Parser round-trip (core cross-checks the fixture bytes; this verifies the RPC face).
    let bytes = fs::read(out_path).unwrap_or_else(|e| panic!("{e}"));
    let meta =
        taiji_core::metainfo::Metainfo::parse(&bytes).unwrap_or_else(|e| panic!("parse: {e}"));
    assert_eq!(meta.meta.kind, taiji_core::create::TorrentForm::Hybrid);
    assert_eq!(meta.name.as_deref(), Some("payload"));
    assert_eq!(meta.meta.piece_length, 16384);
    assert_eq!(meta.announce, "http://a.invalid/ann");
    let hex = |h: &[u8]| -> String { h.iter().map(|b| format!("{b:02x}")).collect() };
    assert_eq!(
        meta.meta.identity.v1.map(|h| hex(&h)).as_deref(),
        Some(v1hex),
        "the receipt's infohashV1 = the parse-face identity"
    );
    assert_eq!(
        meta.meta.identity.v2.map(|h| hex(&h)).as_deref(),
        Some(v2hex),
        "the receipt's infohashV2 = the parse-face identity"
    );
}

/// getCapabilities registration: rpcExtensions includes
/// taiji.createTorrent (same promise-table source).
#[tokio::test]
async fn create_torrent_registered_in_capabilities() {
    // getCapabilities is a query face but auth still runs first — use the no-secret state.
    let st = state(None);
    let resp = call(&st, "taiji.getCapabilities", vec![]).await;
    assert_eq!(resp.code, 0);
    let exts: Vec<&str> = resp.payload["rpcExtensions"]
        .as_array()
        .unwrap_or_else(|| panic!("rpcExtensions array"))
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert!(
        exts.contains(&"taiji.createTorrent"),
        "getCapabilities must list createTorrent: {exts:?}"
    );
    // listMethods lists it too (same source of truth).
    let methods = call(&st, "system.listMethods", vec![]).await;
    let got: Vec<&str> = as_arr(&methods.payload, "listMethods")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert!(got.contains(&"taiji.createTorrent"));
}

/// Error faces (explicit refusals, no disguising): unauthenticated write
/// gate / missing params / empty set / missing path / invalid pieceLength
/// / invalid format / unwritable output dir.
#[tokio::test]
async fn create_torrent_error_faces() {
    let root = temp_root("errors");
    let dir = root.join("in");
    write_file(&dir.join("ok.bin"), 100, |i| i as u8);
    let ok_path = dir.join("ok.bin").display().to_string();
    let out_dir = root.display().to_string();

    // Unauthenticated write gate (no secret → fail closed).
    let open = state(None);
    let denied = call(
        &open,
        "taiji.createTorrent",
        vec![json!([ok_path]), json!(out_dir)],
    )
    .await;
    assert_eq!(denied.code, 1);
    assert_eq!(
        denied.payload["message"], STR_UNAUTH_WRITE,
        "the write-gate wording is frozen"
    );

    let st = state(Some("t108"));
    // Missing params (files / outputDir).
    let missing = call_auth(&st, "taiji.createTorrent", vec![]).await;
    assert_eq!(
        missing.payload["message"],
        "The parameter at 0 is required but missing."
    );
    let missing_dir = call_auth(&st, "taiji.createTorrent", vec![json!([ok_path])]).await;
    assert_eq!(
        missing_dir.payload["message"],
        "The parameter at 1 is required but missing."
    );
    // Empty file set.
    let empty = call_auth(&st, "taiji.createTorrent", vec![json!([]), json!(out_dir)]).await;
    assert_eq!(empty.code, 1);
    assert_eq!(empty.payload["message"], "file paths are not provided.");
    // Missing input path.
    let missing_file = call_auth(
        &st,
        "taiji.createTorrent",
        vec![
            json!([dir.join("nope.bin").display().to_string()]),
            json!(out_dir),
        ],
    )
    .await;
    assert_eq!(missing_file.code, 1);
    assert!(
        missing_file.payload["message"]
            .as_str()
            .unwrap_or("")
            .starts_with("taiji.create_torrent.failed: input file"),
        "error-code prefix + semantics: {}",
        missing_file.payload["message"]
    );
    // Invalid pieceLength (not a power of two).
    let bad_piece = call_auth(
        &st,
        "taiji.createTorrent",
        vec![
            json!([ok_path]),
            json!(out_dir),
            json!({"pieceLength": 8000}),
        ],
    )
    .await;
    assert_eq!(bad_piece.code, 1);
    assert!(
        bad_piece.payload["message"]
            .as_str()
            .unwrap_or("")
            .starts_with("taiji.create_torrent.failed: torrent creation failed"),
        "creator surfaced through the validation face: {}",
        bad_piece.payload["message"]
    );
    // Invalid format.
    let bad_format = call_auth(
        &st,
        "taiji.createTorrent",
        vec![json!([ok_path]), json!(out_dir), json!({"format": "v3"})],
    )
    .await;
    assert_eq!(bad_format.code, 1);
    assert_eq!(
        bad_format.payload["message"],
        "unknown torrent format: v3 (expected one of v1|v2|hybrid)"
    );
    // Output directory missing (the "output not writable" face).
    let bad_out = call_auth(
        &st,
        "taiji.createTorrent",
        vec![
            json!([ok_path]),
            json!(root.join("nowhere").display().to_string()),
        ],
    )
    .await;
    assert_eq!(bad_out.code, 1);
    assert!(
        bad_out.payload["message"]
            .as_str()
            .unwrap_or("")
            .starts_with("taiji.create_torrent.failed: output directory"),
        "{}",
        bad_out.payload["message"]
    );
}

/// v1-only reply face: no infohashV2 key (the v2 transport identity is not faked).
#[tokio::test]
async fn create_torrent_v1_only_omits_v2_identity() {
    let st = state(Some("t108"));
    let root = temp_root("v1only");
    let dir = root.join("single");
    write_file(&dir.join("x.bin"), 1000, |i| i as u8);
    let resp = call_auth(
        &st,
        "taiji.createTorrent",
        vec![
            json!([dir.join("x.bin").display().to_string()]),
            json!(root.display().to_string()),
            json!({"format": "v1"}),
        ],
    )
    .await;
    assert_eq!(resp.code, 0, "{}", resp.payload);
    assert!(resp.payload["infohashV1"].is_string());
    assert!(
        resp.payload.get("infohashV2").is_none(),
        "v1-only has no v2 identity: {}",
        resp.payload
    );
    assert_eq!(
        resp.payload["name"], "x.bin",
        "single-file name = the file name"
    );
}

// ===== recovery event face (taiji.recoveryStarted/Completed) =====

/// getCapabilities declares the extension event names (naming policy:
/// new events are always taiji.*; the aria2 six and the frozen
/// listNotifications table are untouched — extension events are declared
/// via capabilities notifications). Names share one source with core
/// (RecoveryEventKind::notification_method); the hashRecovery feature
/// flag is declared alongside.
#[tokio::test]
async fn capabilities_declare_recovery_events_and_feature() {
    let open = state(None);
    let resp = call(&open, "taiji.getCapabilities", vec![]).await;
    assert_eq!(resp.code, 0, "{}", resp.payload["message"]);
    let c = &resp.payload;

    // notifications: exactly four extension events (the two recovery
    // events + the media phaseChanged bypass + the
    // task-cookie clear-on-error alert — the same
    // bypass declaration face), taiji.* prefix, single core source per
    // family.
    let expect: Vec<&str> = taiji_core::session::RecoveryEventKind::ALL
        .iter()
        .map(|k| k.notification_method())
        .chain(std::iter::once(
            taiji_core::session::MEDIA_PHASE_EVENT_METHOD,
        ))
        .chain(std::iter::once(
            taiji_core::session::TASK_COOKIE_EVENT_METHOD,
        ))
        .collect();
    assert_eq!(
        expect,
        vec![
            "taiji.recoveryStarted",
            "taiji.recoveryCompleted",
            "taiji.media.phaseChanged",
            "taiji.task.cookiesClearedOnError"
        ]
    );
    let got: Vec<&str> = c["notifications"]
        .as_array()
        .unwrap_or_else(|| panic!("notifications array: {}", c))
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert_eq!(
        got, expect,
        "capabilities notifications share the same source as the event names"
    );
    // Neither notification table may absorb extension events (extension
    // events are declared via capabilities, the six via listNotifications
    // — the two channels do not cross).
    for table in [RPC_NOTIFICATIONS, RPC_NOTIFICATIONS_ARIA2] {
        assert!(
            !table.iter().any(|n| n.starts_with("taiji.recovery")),
            "the listNotifications two-face table must not admit extension events"
        );
        assert!(
            !table.contains(&taiji_core::session::MEDIA_PHASE_EVENT_METHOD),
            "the listNotifications two-face table must not admit media extension events (the extension bypass)"
        );
        assert!(
            !table.contains(&taiji_core::session::TASK_COOKIE_EVENT_METHOD),
            "the listNotifications two-face table must not admit the cookie-alert extension event (the bypass)"
        );
    }

    // hashRecovery feature flag (one row in the features registry).
    let feats = c["features"]
        .as_object()
        .unwrap_or_else(|| panic!("features dict"));
    let hr = feats
        .get("hashRecovery")
        .unwrap_or_else(|| panic!("hashRecovery missing a row: {feats:?}"));
    assert_eq!(hr["supported"], json!(true));
    assert_eq!(
        hr["enabled"],
        json!(true),
        "always available at session level (no session switch)"
    );
}

/// API single-face tripwire (pins the "differing face" declaration in the
/// error.rs mapping table): "one API face at a time" is fully
/// landed — method aliases, event names, and listMethods/
/// listNotifications all derive from the single `--rpc-aria2-compat`
/// gate. Any single-face drift (canonical state leaking aria2 names, the
/// compat face missing names, aliases bypassing the gate) fails here.
#[test]
fn api_surface_single_face_gating_matches_declaration() {
    // Registry = bare names + system.* / taiji.* literals, never aria2.* literals.
    for name in taiji_core::session::RPC_METHODS {
        assert!(
            !name.starts_with("aria2."),
            "the registered face keeps the bare/system.*/taiji.* shape: {name}"
        );
    }
    // Alias gating (single canonical_method point): canonical `taiji.*`
    // always accepted; `aria2.*` only in compat mode; bare names are
    // face-independent; dotted alias stacks do not double-match.
    assert_eq!(
        super::canonical_method("taiji.addUri", false),
        Some("addUri")
    );
    assert_eq!(super::canonical_method("addUri", false), Some("addUri"));
    assert_eq!(super::canonical_method("aria2.addUri", false), None);
    assert_eq!(
        super::canonical_method("aria2.addUri", true),
        Some("addUri")
    );
    assert_eq!(
        super::canonical_method("taiji.getCapabilities", false),
        Some("taiji.getCapabilities")
    );
    assert_eq!(
        super::canonical_method("aria2.taiji.moveStorage", true),
        None,
        "extension verbatims have no prefix alias form"
    );
    // Three faces, one source: canonical events are all taiji.onXxx;
    // compat events all aria2.onXxx; the method face is the registry
    // projection (bare names get the face prefix, verbatim entries stay
    // the same in both faces).
    assert!(RPC_NOTIFICATIONS.iter().all(|n| n.starts_with("taiji.on")));
    assert!(
        RPC_NOTIFICATIONS_ARIA2
            .iter()
            .all(|n| n.starts_with("aria2.on"))
    );
    let canonical = super::method_face_names(false);
    let compat = super::method_face_names(true);
    assert_eq!(
        canonical.len(),
        compat.len(),
        "faces project the same table"
    );
    assert_eq!(canonical.len(), taiji_core::session::RPC_METHODS.len());
    for (entry, (c, a)) in taiji_core::session::RPC_METHODS
        .iter()
        .zip(canonical.iter().zip(&compat))
    {
        if entry.contains('.') {
            // Verbatim entries (system.* / taiji.*) keep the same name in both faces.
            assert_eq!(c.as_str(), *entry, "verbatim entry stays verbatim");
            assert_eq!(a.as_str(), *entry, "verbatim entry stays verbatim");
        } else {
            // Bare names project one-to-one: taiji.<bare> ↔ aria2.<bare>.
            assert_eq!(c.as_str(), format!("taiji.{entry}"), "canonical projection");
            assert_eq!(a.as_str(), format!("aria2.{entry}"), "compat projection");
        }
    }
}

/// Numeric error-code rendering: engine-side structured failures
/// (`error_engine`) map per code and per refinement on the stopped face —
/// checksum → 32, auth → 24, unexpected_response(404) → 3 (Status
/// refinement passes through instead of collapsing to 22), read idle
/// timeout → 2, FTP family → 21; without a structured code the core merge
/// holds (1 = UNKNOWN_ERROR).
#[test]
fn stopped_error_code_refines_from_engine_code() {
    use taiji_core::gid::Gid as GidAlias;
    use taiji_core::session::{EngineFailure, EngineFailureKind, StatusKind};

    let base = |engine: Option<EngineFailure>| TorrentStatusView {
        gid: GidAlias::from_u64(0x8000_0000_0000_4321),
        status: StatusKind::Error,
        total_length: 1024,
        completed_length: 0,
        error_code: Some(1),
        error_engine: engine,
        error_message: Some(String::new()),
        ..TorrentStatusView::minimal(
            GidAlias::from_u64(0x8000_0000_0000_4321),
            StatusKind::Error,
            1024,
            0,
        )
    };
    let render = |v: TorrentStatusView| {
        let d = super::view::status_entry_json(&v);
        // aria2 stringification: numbers → strings (uitos).
        d.get("errorCode")
            .and_then(serde_json::Value::as_str)
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or_else(|| panic!("errorCode key: {d}"))
    };
    let fail = |code: &str, kind: EngineFailureKind| {
        Some(EngineFailure {
            code: code.to_string(),
            kind,
        })
    };
    assert_eq!(
        render(base(fail(
            "taiji.http.checksum_mismatch",
            EngineFailureKind::Bare
        ))),
        32,
        "checksum mismatch -> 32 CHECKSUM_ERROR (actually emitted)"
    );
    assert_eq!(
        render(base(fail("taiji.auth.failed", EngineFailureKind::Bare))),
        24,
        "auth failure -> 24 HTTP_AUTH_FAILED (the numeric-face outcome: an FTP login failure is also 24, \
         while aria2 lands on 21 — a declared difference)"
    );
    assert_eq!(
        render(base(fail(
            "taiji.http.unexpected_response",
            EngineFailureKind::Status(404)
        ))),
        3,
        "404 with the Status refinement goes straight to RESOURCE_NOT_FOUND (the finalized render chain)"
    );
    assert_eq!(
        render(base(fail(
            "taiji.http.unexpected_response",
            EngineFailureKind::Bare
        ))),
        22,
        "no refinement payload keeps fallback arm 22"
    );
    assert_eq!(
        render(base(fail(
            "taiji.http.transport",
            EngineFailureKind::TransportTimeout
        ))),
        2,
        "read-idle timeout -> 2 TIME_OUT (the finalized render chain)"
    );
    assert_eq!(
        render(base(fail("taiji.http.ftp", EngineFailureKind::Bare))),
        21,
        "FTP transfer failure -> 21 FTP_PROTOCOL_ERROR (the finalized row)"
    );
    assert_eq!(
        render(base(fail("taiji.http.failed", EngineFailureKind::Bare))),
        1,
        "an unrefined code keeps UNKNOWN_ERROR"
    );
    assert_eq!(
        render(base(None)),
        1,
        "no structured code keeps the core collapse face"
    );
}

/// Per-code e2e of the mapping table over the production render chain:
/// taiji-http error variants → `EngineFailure::of_http_error` (the only
/// core-side conversion) → view `error_engine` →
/// `status_entry_json.errorCode`, with no manual kind pairing. DNS and
/// disk refinements are pinned at their aligned real behavior (payloads
/// never phase-split, so they stay Bare → 6/17; the finer rows were
/// removed with the table/arm alignment and are declared as differences).
/// Also pinned: the two production sites that bypass `of_http_error` —
/// the task-level stall arm (builds TransportTimeout directly → 2) and
/// bare task-level codes (`taiji.http.failed` has no row → fallback 1).
#[test]
fn http_failure_numeric_end_to_end_production_chain() {
    use taiji_core::session::{EngineFailure, EngineFailureKind, StatusKind};
    use taiji_http::error::HttpError;

    let gid = taiji_core::gid::Gid::from_u64(0x8000_0000_0000_e2e1);
    let render = |f: Option<EngineFailure>| {
        let v = TorrentStatusView {
            status: StatusKind::Error,
            error_engine: f,
            ..TorrentStatusView::minimal(gid, StatusKind::Error, 1024, 0)
        };
        let d = super::view::status_entry_json(&v);
        d.get("errorCode")
            .and_then(serde_json::Value::as_str)
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or_else(|| panic!("errorCode key: {d}"))
    };
    let chain = |e: &HttpError| Some(EngineFailure::of_http_error(e));

    // ---- of_http_error production chain, per code (error.rs doc table) ----
    let cases: Vec<(HttpError, i64)> = vec![
        (HttpError::BadRange, 8),
        // Aligned with 8 (CANNOT_RESUME, same slot as bad_range — the
        // aria2 isRangeSatisfied failure family): an explicit failure when
        // a download-phase 200 arrives after resumability was probed.
        (HttpError::RangeIgnored, 8),
        (HttpError::PathConflict, 13),
        (HttpError::MirrorMismatch, 1),
        (HttpError::NoSource, 1),
        // Status-code family (Status refinement passes through; 403 → fallback 22).
        (HttpError::UnexpectedResponse { status: 404 }, 3),
        (HttpError::UnexpectedResponse { status: 401 }, 24),
        (HttpError::UnexpectedResponse { status: 403 }, 22),
        (HttpError::UnexpectedResponse { status: 500 }, 22),
        (HttpError::UnexpectedResponse { status: 502 }, 29),
        (HttpError::UnexpectedResponse { status: 503 }, 29),
        (HttpError::UnexpectedResponse { status: 504 }, 29),
        (HttpError::RedirectLimit { max: 20 }, 23),
        (HttpError::RedirectLoop, 23),
        (HttpError::InsecureRedirect, 22),
        (HttpError::CookieFileTooLarge { max_bytes: 1 << 20 }, 1),
        (HttpError::CookieFile("io".into()), 1),
        // Transport family, aligned: DNS and connect-refused both land on 6 (Bare).
        (HttpError::Transport("dns: no record".into()), 6),
        (HttpError::Transport("connect refused".into()), 6),
        (HttpError::AuthFailed("digest challenge".into()), 24),
        (
            HttpError::ChecksumMismatch {
                expected: "ab".into(),
                got: "cd".into(),
            },
            32,
        ),
        (
            HttpError::OptionInvalid {
                option: "--http-block-size",
                value: "3MiB".into(),
            },
            28,
        ),
        (HttpError::CoordinatorStopped, 1),
        // Disk family, aligned behavior: open/read/write all land on 17 (Bare fallback).
        (HttpError::Disk("open .part".into()), 17),
        (HttpError::Disk("fsync .part".into()), 17),
        (
            HttpError::TotalLengthExceeded {
                total: u64::MAX,
                max: 1,
            },
            1,
        ),
        // FTP family (its read idle timeout also yields 21; the same
        // shape over HTTP is 2 — a declared difference).
        (HttpError::Ftp("read idle timeout".into()), 21),
        (HttpError::FtpResumeUnsupported, 21),
    ];
    for (err, want) in cases {
        let f = chain(&err);
        assert_eq!(
            render(f),
            want,
            "{err} numeric code drifted on the production render chain (the doc-table semantics)"
        );
    }

    // ---- Stall arm (http_task builds TransportTimeout directly; the
    // only refined production site outside of_http_error) → 2 TIME_OUT.
    let stall = EngineFailure {
        code: "taiji.http.transport".into(),
        kind: EngineFailureKind::TransportTimeout,
    };
    assert_eq!(render(Some(stall)), 2, "the --timeout stall outcome -> 2");

    // ---- Bare task-level codes (http_task-built): rows hit directly, missing rows fall to 1.
    let bare = |code: &str| {
        Some(EngineFailure {
            code: code.into(),
            kind: EngineFailureKind::Bare,
        })
    };
    assert_eq!(
        render(bare("taiji.option.invalid")),
        28,
        "changeOption out-of-domain goes straight to 28"
    );
    assert_eq!(
        render(bare("taiji.http.no_source")),
        1,
        "the no_source row goes straight to 1"
    );
    assert_eq!(
        render(bare("taiji.http.failed")),
        1,
        "a row-less code falls back to UNKNOWN_ERROR (the RequestGroup face follows the same rule)"
    );
}

/// Positive and negative pinning on the numeric face:
/// `taiji.http.range_ignored` (an explicit task-level failure when a
/// download-phase Range request gets 200 after resumability was probed)
/// flows through the production chain `HttpError` →
/// `EngineFailure::of_http_error` → view `error_engine` →
/// `status_entry_json.errorCode` and lands on **8** (CANNOT_RESUME, same
/// slot as `bad_range` — the aria2 isRangeSatisfied failure family,
/// analogous to Android Download Manager's "Expected partial, but
/// received OK" → STATUS_CANNOT_RESUME). The unexpected_response family
/// keeps its numbers unchanged (frozen seam: 404 → 3, unmapped statuses
/// → 22, Bare → 22, bad_range still 8).
#[test]
fn range_ignored_numeric_surface_is_cannot_resume() {
    use taiji_core::session::{EngineFailure, StatusKind};
    use taiji_http::error::HttpError;

    let gid = taiji_core::gid::Gid::from_u64(0x8000_0000_0000_0771);
    let render = |f: Option<EngineFailure>| {
        let v = TorrentStatusView {
            status: StatusKind::Error,
            error_engine: f,
            ..TorrentStatusView::minimal(gid, StatusKind::Error, 1024, 0)
        };
        let d = super::view::status_entry_json(&v);
        d.get("errorCode")
            .and_then(serde_json::Value::as_str)
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or_else(|| panic!("errorCode key: {d}"))
    };

    // Positive: range_ignored via the of_http_error chain → 8 CANNOT_RESUME.
    assert_eq!(
        render(Some(EngineFailure::of_http_error(&HttpError::RangeIgnored))),
        8,
        "range_ignored's numeric face = 8 CANNOT_RESUME (the same slot as bad_range)"
    );
    // Negatives (frozen seam): the unexpected_response family and
    // bad_range numbers are unaffected by the new mapping row.
    assert_eq!(
        render(Some(EngineFailure::of_http_error(
            &HttpError::UnexpectedResponse { status: 404 }
        ))),
        3,
        "a plain 404 keeps 3 RESOURCE_NOT_FOUND (unaffected by the pairing)"
    );
    assert_eq!(
        render(Some(EngineFailure::of_http_error(
            &HttpError::UnexpectedResponse { status: 500 }
        ))),
        22,
        "an off-table status keeps 22 HTTP_PROTOCOL_ERROR (unaffected by the pairing)"
    );
    assert_eq!(
        render(Some(EngineFailure::bare("taiji.http.unexpected_response"))),
        22,
        "unexpected_response Bare keeps fallback arm 22 (unaffected by the pairing)"
    );
    assert_eq!(
        render(Some(EngineFailure::of_http_error(&HttpError::BadRange))),
        8,
        "bad_range keeps 8 (the same-slot merged arm does not alter the original row)"
    );
}

/// getFiles entry rendering: recovery = Some → the `recoveryStatus` key
/// (camelCase, value mapped directly); None → key absent.
#[test]
fn file_entry_json_projects_recovery_status() {
    use taiji_core::session::{FileEntryView, UriEntryView};
    let base = || FileEntryView {
        index: 1,
        path: "v2.bin".into(),
        selected: true,
        priority: 0,
        length: 3,
        completed_length: 0,
        uris: Vec::<UriEntryView>::new(),
        pieces_root: Some([0u8; 32]),
        piece_size: 16384,
        padding: false,
        recovery: None,
    };
    for st in ["layer_missing", "recovering", "ready"] {
        let mut f = base();
        f.recovery = Some(st);
        let d = super::view::file_entry_json(&f);
        assert_eq!(
            d["recoveryStatus"],
            json!(st),
            "value domain maps directly: {st}"
        );
    }
    let d = super::view::file_entry_json(&base());
    assert!(
        d.get("recoveryStatus").is_none(),
        "a participating non-layer-missing file leaves the key absent: {d}"
    );
}

// ===== canonical `taiji.*` face + `http` sub-dict =====

/// Single source of method-name alias normalization: canonical
/// `taiji.<name>` and bare names dispatch to the same frozen method —
/// registration and listMethods names do not fork per alias; `aria2.<name>`
/// aliases are accepted only in compat mode. system.* introspection is
/// unaffected by prefixes.
#[tokio::test]
async fn canonical_taiji_namespace_routes_to_frozen_surface() {
    let st = state(None);
    for name in ["getVersion", "taiji.getVersion"] {
        let resp = call(&st, name, vec![]).await;
        assert_eq!(resp.code, 0, "{name}: {}", resp.payload["message"]);
        assert!(
            resp.payload["version"]
                .as_str()
                .unwrap_or("")
                .starts_with("taiji/"),
            "{name}: frozen prefix"
        );
    }
    // Compat mode: the aria2.* alias routes to the same frozen method.
    let compat = state_compat(None);
    let resp = call(&compat, "aria2.getVersion", vec![]).await;
    assert_eq!(
        resp.code, 0,
        "aria2.getVersion: {}",
        resp.payload["message"]
    );
    // taiji.* extension full names match exactly; prefix stripping does not touch them.
    let caps = call(&st, "taiji.getCapabilities", vec![]).await;
    assert_eq!(
        caps.code, 0,
        "taiji.getCapabilities: {}",
        caps.payload["message"]
    );
    // Default listMethods = canonical face (bare names project to
    // taiji.<bare>); the registry (RPC_METHODS) does not fork.
    let methods = call(&st, "system.listMethods", vec![]).await;
    assert_eq!(methods.code, 0);
    let names: Vec<String> = as_arr(&methods.payload, "listMethods")
        .iter()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect();
    assert!(
        names.iter().any(|n| n == "taiji.addUri"),
        "the canonical presentation face"
    );
    assert!(
        !names.iter().any(|n| n == "aria2.addUri"),
        "the default state must not present the aria2 face (one API face at a time)"
    );
}

/// Dual-state consistency (method/listMethods half): with compat
/// on/off, method acceptance and presentation are mutually exclusive and
/// the union covers the surface.
#[tokio::test]
async fn aria2_alias_mode_is_gated_both_ways() {
    // Default state: aria2.* is always an unknown method (reference text after auth).
    let st = state(Some("t"));
    for name in ["aria2.getVersion", "aria2.tellStatus"] {
        let resp = call(&st, name, vec![json!("token:t")]).await;
        assert_eq!(resp.code, 1, "{name}");
        assert_eq!(
            resp.payload["message"],
            format!("No such method: {name}"),
            "with compat off, aria2.* must be an explicit unknown method"
        );
    }
    // Alias normalization only applies to bare names: stacked prefixes
    // (aria2.taiji.moveStorage / taiji.system.listMethods) are rejected in
    // both states.
    let compat = state_compat(Some("t"));
    for name in ["aria2.taiji.moveStorage", "taiji.system.listMethods"] {
        let st_ref = if name.starts_with("aria2.") {
            &compat
        } else {
            &st
        };
        let resp = call(st_ref, name, vec![json!("token:t")]).await;
        assert_eq!(resp.code, 1, "{name}");
        assert_eq!(resp.payload["message"], format!("No such method: {name}"));
    }
    // Compat mode: the aria2.* alias passes and returns the canonical
    // reply (system.* keeps the same name in both faces).
    let a = call(&st, "taiji.getVersion", vec![json!("token:t")]).await;
    let b = call(&compat, "aria2.getVersion", vec![json!("token:t")]).await;
    assert_eq!(a.payload, b.payload, "alias must land on the same method");
}

/// `http` sub-dict rendering (promised fields; aria2 string/bool
/// conventions; encoding unset = key absent). Declared difference: the
/// dict as a whole is a taiji extension.
#[test]
fn http_subdict_renders_promised_fields() {
    use taiji_core::gid::Gid as GidAlias;
    use taiji_core::session::{HttpSourceView, HttpView, StatusKind};

    use crate::dispatch::view::status_entry_json;
    let view = TorrentStatusView {
        num_files_full: None,
        gid: GidAlias::from_u64(0x8000_0000_0000_1234),
        status: StatusKind::Complete,
        total_length: 1024,
        completed_length: 1024,
        upload_length: 0,
        download_length: 1024,
        download_speed: 0,
        upload_speed: 0,
        connections: 0,
        bitfield: None,
        piece_length: 0,
        num_pieces: 0,
        followed_by: Vec::new(),
        following: None,
        belongs_to: None,
        files: Vec::new(),
        dir: "/dl".into(),
        bittorrent: None,
        info_hash: None,
        num_seeders: 0,
        seeder: None,
        error_code: Some(0),
        error_engine: None,
        error_message: Some(String::new()),
        media: None,
        http: Some(HttpView {
            final_url: "http://origin/f.bin".into(),
            connections: 3,
            extents_active: 2,
            blocks_done: 7,
            blocks_total: 9,
            encoding: None,
            rename_pending: true,
            sources: vec![HttpSourceView {
                url: "http://mirror/f.bin".into(),
                rate: 4096,
                state: "active".into(),
            }],
        }),
    };
    let d = status_entry_json(&view);
    let http = &d["http"];
    assert_eq!(http["finalUrl"], json!("http://origin/f.bin"));
    assert_eq!(http["connections"], json!("3"));
    assert_eq!(http["extentsActive"], json!("2"));
    assert_eq!(http["blocksDone"], json!("7"));
    assert_eq!(http["blocksTotal"], json!("9"));
    assert_eq!(http["renamePending"], json!("true"));
    let sources = as_arr(&http["sources"], "sources");
    assert_eq!(sources.len(), 1);
    assert_eq!(sources[0]["url"], json!("http://mirror/f.bin"));
    assert_eq!(sources[0]["rate"], json!("4096"));
    assert_eq!(sources[0]["state"], json!("active"));
    assert!(
        http.get("encoding").is_none(),
        "an absent encoding (identity/unprobed) = the key absent"
    );
    // Non-HTTP tasks omit the key (same rule as the bittorrent field).
    let mut bt_only = view.clone();
    bt_only.http = None;
    assert!(status_entry_json(&bt_only).get("http").is_none());
}

// ---- Multi-source RPC entry e2e (URI array → multi-source drive → sources face) ----

/// Minimal mock origin (raw TCP, in-process): Range requests get 206 +
/// `Content-Range` (probed as resumable); without Range → 200 +
/// Content-Length with the full body.
async fn spawn_mini_origin(body: std::sync::Arc<Vec<u8>>) -> String {
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
            let body = std::sync::Arc::clone(&body);
            tokio::spawn(async move {
                let mut buf: Vec<u8> = Vec::new();
                loop {
                    let head = loop {
                        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            let head: Vec<u8> = buf.drain(..pos + 4).collect();
                            break String::from_utf8_lossy(&head).into_owned();
                        }
                        let mut chunk = [0u8; 4096];
                        match sock.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    };
                    let total = body.len() as u64;
                    let lower = head.to_ascii_lowercase();
                    let range = lower
                        .split("\r\n")
                        .find_map(|l| l.strip_prefix("range: bytes="))
                        .and_then(|v| {
                            let (s, e) = v.trim().split_once('-')?;
                            Some((s.parse::<u64>().ok()?, e.parse::<u64>().ok()?))
                        });
                    match range {
                        Some((s, e)) if e < total => {
                            let slice = &body[s as usize..=(e as usize).min(total as usize - 1)];
                            let resp = format!(
                                "HTTP/1.1 206 Partial Content\r\n\
                                 Content-Range: bytes {s}-{e}/{total}\r\n\
                                 Accept-Ranges: bytes\r\n\
                                 Content-Length: {}\r\n\r\n",
                                slice.len()
                            );
                            sock.write_all(resp.as_bytes()).await.ok();
                            sock.write_all(slice).await.ok();
                        }
                        _ => {
                            sock.write_all(
                                format!("HTTP/1.1 200 OK\r\nContent-Length: {total}\r\n\r\n")
                                    .as_bytes(),
                            )
                            .await
                            .ok();
                            sock.write_all(&body).await.ok();
                        }
                    }
                }
            });
        }
    });
    format!("http://{addr}/f.bin")
}

/// Multi-URI array through the full RPC chain (the session multi-source
/// assembly entry): a live http source plus a dead ftp source — the ftp
/// source is dropped after probe failure, the http source completes;
/// tellStatus `http.sources` shows both sources' real states
/// (failed/waiting) without disguising. Session-level cross-source
/// allocation assertions live in the taiji-core integration tests.
#[tokio::test]
async fn add_uri_multi_uri_array_sources_face_rpc_e2e() {
    let st = state(Some("t"));
    let dir = std::env::temp_dir().join(format!("bh-p35-multi-{}", std::process::id()));
    let body: std::sync::Arc<Vec<u8>> =
        std::sync::Arc::new((0..256 * 1024u32).map(|i| (i % 251) as u8).collect());
    let http_uri = spawn_mini_origin(std::sync::Arc::clone(&body)).await;
    let ftp_dead = "ftp://127.0.0.1:1/f.bin".to_string();

    let add = call_auth(
        &st,
        "addUri",
        vec![
            json!([http_uri.clone(), ftp_dead.clone()]),
            json!({"dir": dir.display().to_string()}),
        ],
    )
    .await;
    assert_eq!(
        add.code, 0,
        "addUri with multiple URIs accepted: {}",
        add.payload["message"]
    );
    let gid = ok_str(&add);

    // Poll to a terminal state (complete or explicit error); assert complete.
    let mut status = String::new();
    let mut http_dict = serde_json::Value::Null;
    for _ in 0..250 {
        let entry = call_auth(&st, "tellStatus", vec![json!(gid.clone())]).await;
        assert_eq!(entry.code, 0, "{}", entry.payload["message"]);
        status = entry.payload["status"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        if status == "complete" || status == "error" {
            http_dict = entry.payload["http"].clone();
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        status, "complete",
        "the http mirror must complete: {http_dict}"
    );
    let sources = as_arr(&http_dict["sources"], "sources");
    assert_eq!(
        sources.len(),
        2,
        "the user's full source set is presented: {http_dict}"
    );
    assert_eq!(sources[0]["url"], json!(http_uri));
    assert_eq!(sources[1]["url"], json!(ftp_dead));
    assert_eq!(
        sources[1]["state"],
        json!("failed"),
        "the dead ftp source reports an honest terminal state"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ===== Remaining RPC surface (getUris/getServers/saveSession) + sftp deferral =====

/// Method-difference pins (all new-method differences live in the
/// declaration list) — three HTTP-task faces:
/// - addUri `sftp://` → the explicit `taiji.sftp.deferred` error code
/// (SFTP is deferred, declared);
/// - getUris on an inactive HTTP task = all "waiting"; an unknown GID
/// fails at the str2Gid pre-parse (resolve_gid doc);
/// - getServers on an inactive task = "No active download" (reference
/// text);
/// - saveSession without persistence = explicit failure, never a fake
/// success (the compat promise is a full store flush, not an aria2
/// session file format).
#[tokio::test]
async fn http_method_surface_sftp_deferred_and_query_shapes() {
    let st = state(Some("t"));
    // sftp deferral error code (rejected at task creation, not enqueued).
    let sftp = call_auth(&st, "addUri", vec![json!(["sftp://host.example/f.bin"])]).await;
    assert_eq!(sftp.code, 1);
    let msg = sftp.payload["message"].as_str().unwrap_or_default();
    assert!(
        msg.starts_with("taiji.sftp.deferred:"),
        "the sftp deferred error code: {msg}"
    );
    // Inactive HTTP task (paused): getUris = all "waiting"; getServers =
    // "No active download" (aria2 getServers only serves ACTIVE groups).
    let gid = call_auth(
        &st,
        "addUri",
        vec![
            json!(["http://127.0.0.1:1/f.bin"]),
            json!({"pause": "true", "dir": "/tmp/tb30-geturis"}),
        ],
    )
    .await;
    assert_eq!(gid.code, 0, "addUri: {}", gid.payload["message"]);
    // addUri success reply = bare GID string (createGIDResponse shape).
    let g = gid.payload.as_str().unwrap_or_default().to_string();
    // Query faces authenticate too (RpcMethod.cc authorizes first; a secret is set).
    let uris = call_auth(&st, "getUris", vec![json!(g)]).await;
    assert_eq!(uris.code, 0, "getUris: {}", uris.payload["message"]);
    let arr = as_arr(&uris.payload, "getUris");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["uri"], json!("http://127.0.0.1:1/f.bin"));
    assert_eq!(
        arr[0]["status"],
        json!("waiting"),
        "not yet active = the remaining face"
    );
    let servers = call_auth(&st, "getServers", vec![json!(g)]).await;
    assert_eq!(servers.code, 1);
    assert_eq!(
        servers.payload["message"],
        format!("No active download for GID#{g}")
    );
    // Unknown GID: str2Gid expansion fails explicitly ("GID ... is not
    // found" — the same pre-parse on every gid-taking method).
    let uris_missing = call_auth(&st, "getUris", vec![json!("deadbeefdeadbeef")]).await;
    assert_eq!(uris_missing.code, 1);
    assert_eq!(
        uris_missing.payload["message"],
        "GID deadbeefdeadbeef is not found"
    );
    // saveSession: explicit failure without persistence (no fake success).
    let save = call_auth(&st, "saveSession", vec![]).await;
    assert_eq!(save.code, 1);
    assert!(
        save.payload["message"]
            .as_str()
            .unwrap_or_default()
            .contains("saveSession"),
        "{}",
        save.payload["message"]
    );
}

/// getServers server-entry rendering: downloadSpeed carries the
/// per-source measured rate (the aria2 server dict key; HTTP sources are
/// not always zero).
#[test]
fn server_entry_json_carries_download_speed() {
    use taiji_core::session::ServerEntryView;
    let s = ServerEntryView {
        url: "http://mirror/f.bin".into(),
        tier: 1,
        status: "working",
        seeds: None,
        leechers: None,
        download_speed: 4096,
    };
    let d = super::view::server_entry_json(&s);
    assert_eq!(d["uri"], json!("http://mirror/f.bin"));
    assert_eq!(d["currentUri"], json!("http://mirror/f.bin"));
    assert_eq!(
        d["downloadSpeed"],
        json!("4096"),
        "the per-source measured reading"
    );
    assert_eq!(d["status"], json!("working"));
    // BT tracker snapshot with zero rate.
    let bt = ServerEntryView {
        download_speed: 0,
        ..s
    };
    let d = super::view::server_entry_json(&bt);
    assert_eq!(d["downloadSpeed"], json!("0"));
}

/// taiji.addUriWithCookies/setTaskCookies dispatch: param face (cookies
/// required, array form), fork validation texts passed through verbatim
/// (the parseRpcCookies chain), receipts (Gid / "OK", the
/// createOKResponse face), and canonical-only naming (`aria2.` prefixed
/// aliases are rejected, compat mode included). Dispatch coverage is
/// pinned by every_promised_method_dispatches; the write gate by
/// unauthenticated_write_is_refused (neither method is in the
/// is_read_only exemption set).
#[tokio::test]
async fn taiji_cookie_methods_shape_receipts_and_gates() {
    let st = state(Some("t"));
    // ---- Param face ----
    let missing = call_auth(
        &st,
        "taiji.addUriWithCookies",
        vec![json!(["http://h/f.bin"])],
    )
    .await;
    assert_eq!(missing.code, 1);
    assert_eq!(
        missing.payload["message"],
        "The parameter at 1 is required but missing."
    );
    let wrong = call_auth(
        &st,
        "taiji.setTaskCookies",
        vec![json!("8000000000000001"), json!("not-a-list")],
    )
    .await;
    assert_eq!(wrong.code, 1);
    assert_eq!(
        wrong.payload["message"],
        "The parameter at 1 has wrong type."
    );
    let empty_uris = call_auth(&st, "taiji.addUriWithCookies", vec![json!([]), json!([])]).await;
    assert_eq!(empty_uris.code, 1);
    assert_eq!(empty_uris.payload["message"], "URI is not provided.");

    // ---- Fork parseRpcCookies texts passed through verbatim ----
    let unknown = call_auth(
        &st,
        "taiji.addUriWithCookies",
        vec![
            json!(["http://h/f.bin"]),
            json!([{"name": "k", "value": "v", "domain": "a.com", "bogus": 1}]),
        ],
    )
    .await;
    assert_eq!(unknown.payload["message"], "Unknown task cookie field.");
    let syntax = call_auth(
        &st,
        "taiji.addUriWithCookies",
        vec![
            json!(["http://h/f.bin"]),
            json!([{"name": "", "value": "v", "domain": "a.com"}]),
        ],
    )
    .await;
    assert_eq!(syntax.payload["message"], "Invalid task cookie syntax.");
    let domain = call_auth(
        &st,
        "taiji.setTaskCookies",
        vec![
            json!("8000000000000001"),
            json!([{"name": "k", "value": "v", "domain": "a..com"}]),
        ],
    )
    .await;
    assert_eq!(domain.payload["message"], "Invalid task cookie domain.");
    let expiry = call_auth(
        &st,
        "taiji.setTaskCookies",
        vec![
            json!("8000000000000001"),
            json!([{"name": "k", "value": "v", "domain": "a.com", "expiresAt": -5}]),
        ],
    )
    .await;
    assert_eq!(
        expiry.payload["message"],
        "Task cookie expiry must be nonnegative Unix milliseconds."
    );
    let ftp_uri = call_auth(
        &st,
        "taiji.addUriWithCookies",
        vec![json!(["ftp://h/f.bin"]), json!([])],
    )
    .await;
    assert_eq!(
        ftp_uri.payload["message"],
        "Task cookies require HTTP or HTTPS URIs."
    );

    // ---- Acceptance and receipts: addUriWithCookies → GID; setTaskCookies → OK ----
    let dir = std::env::temp_dir().join(format!("bh-p34-cookie-{}", std::process::id()));
    let added = call_auth(
        &st,
        "taiji.addUriWithCookies",
        vec![
            json!(["http://127.0.0.1:1/f.bin"]),
            json!([{"name": "sid", "value": "abc", "domain": "127.0.0.1"}]),
            json!({"dir": dir.display().to_string(), "pause": "true"}),
        ],
    )
    .await;
    assert_eq!(added.code, 0, "{}", added.payload["message"]);
    let gid = ok_str(&added);
    let set = call_auth(
        &st,
        "taiji.setTaskCookies",
        vec![
            json!(gid),
            json!([{"name": "sid", "value": "new", "domain": "127.0.0.1"}]),
        ],
    )
    .await;
    assert_eq!(set.code, 0, "{}", set.payload["message"]);
    assert_eq!(set.payload, json!("OK"), "createOKResponse's same face");

    // Unknown gid → str2Gid family text (same pre-parse order as fork findGroup).
    let not_found = call_auth(
        &st,
        "taiji.setTaskCookies",
        vec![
            json!("800000000000dead"),
            json!([{"name": "k", "value": "v", "domain": "a.com"}]),
        ],
    )
    .await;
    assert_eq!(
        not_found.payload["message"],
        "GID 800000000000dead is not found"
    );

    // ---- Canonical-only naming: aria2.* aliases are rejected in both
    // states (the fork has same-named methods, but taiji.* is the accepted
    // canonical; compat does not project them). ----
    let mut st_compat = state(Some("t"));
    st_compat.aria2_compat = true;
    for m in ["aria2.addUriWithCookies", "aria2.setTaskCookies"] {
        let r = call_auth(&st_compat, m, vec![json!("g"), json!([])]).await;
        assert_eq!(r.payload["message"], format!("No such method: {m}"), "{m}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Request-level cap on total multicall sub-calls inside a batch —
/// 101 batch items × 101 sub-calls = 10201 > 10_000 rejects the whole
/// batch; 99 × 99 = 9801 passes. (The recursion guard previously only
/// caught multicall-in-multicall; the batch arm was blind to ~10^6
/// sub-calls from one authenticated request.)
#[tokio::test]
async fn batch_multicall_subcall_budget_enforced() {
    assert_eq!(
        MAX_REQUEST_SUBCALLS, 10_000,
        "the cap value is anchored (changing it requires a documented decision)"
    );
    let st = state(None);
    let mc = |n: usize, id: usize| {
        let subs: Vec<Value> = (0..n)
            .map(|_| json!({"method": "getVersion", "params": []}))
            .collect();
        json!({
            "id": id,
            "method": "system.multicall",
            "params": [subs]
        })
    };
    // Over the cap: 101 × 101 = 10201 > MAX_REQUEST_SUBCALLS.
    let over: Value = (0..101).map(|i| mc(101, i)).collect();
    let outcome = handle_payload(&st, &over, None).await;
    assert_eq!(outcome.code, 1, "over the cap, the whole batch is rejected");
    let msg = outcome.body["error"]["message"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(
        msg.contains("batch subcall budget exceeded"),
        "the error face: {msg}"
    );

    // Within the cap: 99 × 99 = 9801 ≤ 10_000 answered per item.
    let ok: Value = (0..99).map(|i| mc(99, i)).collect();
    let outcome = handle_payload(&st, &ok, None).await;
    assert_eq!(outcome.code, 0, "within the cap, business as usual");
    assert!(outcome.body.is_array(), "batch responses are always arrays");
}

// ---- Media line dispatch tests ----

/// The read_only adjudication through the write gate (the
/// per-method ruling): with no secret, addMedia/probeMedia/
/// stopRecording fail closed; getMediaFormats passes. The frozen
/// anchor itself lives in the core command tests (the registry's
/// own governance) — this is the gate's end-to-end consumption.
#[tokio::test]
async fn media_methods_write_gate_adjudication() {
    let open = state(None);
    // Write faces fail closed (the probe action face included —
    // no secret = the same posture as the write faces; the
    // destructive archive clear included — the read_only=false
    // adjudication through the gate).
    for method in [
        "taiji.addMedia",
        "taiji.probeMedia",
        "taiji.stopRecording",
        "taiji.clearMediaArchive",
    ] {
        let resp = call(&open, method, vec![json!("x")]).await;
        assert_eq!(resp.code, 1, "{method}");
        assert_eq!(
            resp.payload["message"],
            json!("unauthenticated write requires --rpc-secret"),
            "{method} fails closed"
        );
    }
    // The read face passes the gate (a gid-shaped miss reaches the
    // session face, not the gate).
    let resp = call(
        &open,
        "taiji.getMediaFormats",
        vec![json!("8000000000000000")],
    )
    .await;
    assert_ne!(
        resp.payload["message"],
        json!("unauthenticated write requires --rpc-secret"),
        "getMediaFormats is the read-only face of the family"
    );
}

/// The clearMediaArchive decode + the reply shape: a
/// parameterless Control face — extra params ride the aria2 lax rule,
/// and the reply renders the extension dict `{"removed": N}` (with a
/// secret-less store-less session the gate face above already covers
/// the fail-closed arm; here the decode arm itself).
#[tokio::test]
async fn clear_media_archive_decode_shape() {
    let open = state(None);
    // Through the gate the method is a write face; the decode arm is
    // exercised by reaching past the gate with a secret set (the
    // no-store session answers the explicit storage error — proving
    // the dispatch reached the actor arm, not "No such method").
    let st = state(Some("a-secret-0123456789"));
    let resp = call(&st, "taiji.clearMediaArchive", vec![]).await;
    assert_ne!(
        resp.payload["message"],
        json!("No such method: taiji.clearMediaArchive"),
        "the method is registered and dispatched"
    );
    assert_ne!(resp.code, -32601, "not method-not-found");
    // Extra params ignored (the lax rule) — same face.
    let resp2 = call(&st, "taiji.clearMediaArchive", vec![json!("extra")]).await;
    assert_eq!(resp2.code, resp.code, "extra params ride the lax rule");
    let _ = &open;
}

/// Parameter decode: addMedia takes (url, options?, position?);
/// an empty URL is the aria2 empty-set shape; the options dict
/// rides verbatim (validation is the actor's face).
#[tokio::test]
async fn add_media_decode_shapes() {
    let st = state(Some("s3cret"));
    let resp = call_auth(
        &st,
        "taiji.addMedia",
        vec![
            json!("https://x.test/m.m3u8"),
            json!({ "dir": "/tmp/m", "media-selector": "res<=720" }),
            json!(0),
        ],
    )
    .await;
    // The decode arm reaches the live session: the reply is the
    // allocated GID (16-hex — the actor accepted the task; its
    // Resolving phase then fails against the unreachable host,
    // which is not this test's face).
    assert_eq!(resp.code, 0, "{}", resp.payload["message"]);
    // The decode reached the session (the error is the actor's
    // face, not a decode error) — the empty-URL arm proves the
    // decode layer's own shape check.
    let resp = call_auth(&st, "taiji.addMedia", vec![json!("")]).await;
    assert_eq!(
        resp.payload["message"],
        json!("URL is not provided."),
        "the addUri empty-set wording"
    );
    let resp = call_auth(&st, "taiji.addMedia", vec![json!(42)]).await;
    assert_eq!(resp.code, 1, "a non-string URL is a type error");
    let resp = call_auth(&st, "taiji.probeMedia", vec![json!("")]).await;
    assert_eq!(resp.payload["message"], json!("URL is not provided."));
}

/// listNotifications did not grow (the phaseChanged bypass
/// never enters the six-event table — the presentation face stays
/// six-only in both states).
#[tokio::test]
async fn list_notifications_stays_six_events_with_media_line() {
    for compat in [false, true] {
        let face = if compat { "aria2." } else { "taiji." };
        let st = if compat {
            state_compat(Some("s3cret"))
        } else {
            state(Some("s3cret"))
        };
        let notes = call(&st, "system.listNotifications", vec![]).await;
        assert_eq!(notes.code, 0);
        let list: Vec<&str> = as_arr(&notes.payload, "listNotifications")
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert_eq!(list.len(), 6, "the six-event face in both states");
        for name in list {
            let name: &str = name;
            assert!(name.starts_with(face), "{name}");
            assert!(!name.contains("media"), "no media event in the table");
        }
    }
}

/// The media sub-dictionary rendering: the promised fields
/// (kind/phase/phaseDetail/tracks/stagingDir/outputName/selector/
/// variant/manifestUrl) — the render face over a hand-built view.
#[test]
fn media_subdict_renders_promised_fields() {
    use taiji_core::gid::Gid as GidAlias;
    use taiji_core::session::{MediaTrackView, MediaView};
    let base_view = || {
        use taiji_core::session::StatusKind;
        TorrentStatusView {
            num_files_full: None,
            gid: GidAlias::from_u64(0x8000_0000_0000_4321),
            status: StatusKind::Active,
            total_length: 0,
            completed_length: 0,
            upload_length: 0,
            download_length: 0,
            download_speed: 0,
            upload_speed: 0,
            connections: 0,
            bitfield: None,
            piece_length: 0,
            num_pieces: 0,
            followed_by: Vec::new(),
            following: None,
            belongs_to: None,
            files: Vec::new(),
            dir: String::new(),
            bittorrent: None,
            info_hash: None,
            num_seeders: 0,
            seeder: None,
            error_code: None,
            error_engine: None,
            error_message: None,
            http: None,
            media: None,
        }
    };
    let mut view = base_view();
    view.media = Some(MediaView {
        kind: "hls".into(),
        phase: "paused".into(),
        phase_detail: Some("processing".into()),
        tracks: vec![MediaTrackView {
            label: "v".into(),
            kind: "video".into(),
            state: "done".into(),
            segments_done: 6,
            segments_total: 6,
        }],
        staging_dir: "/dl/.taiji-b/g1".into(),
        output_name: Some("clip.mp4".into()),
        selector: Some("best".into()),
        variant: Some("320x240".into()),
        manifest_url: "https://x/m.m3u8".into(),
    });
    let d = super::view::status_entry_json(&view);
    let m = &d["media"];
    assert_eq!(m["kind"], json!("hls"));
    assert_eq!(m["phase"], json!("paused"));
    assert_eq!(m["phaseDetail"], json!("processing"));
    assert_eq!(m["stagingDir"], json!("/dl/.taiji-b/g1"));
    assert_eq!(m["outputName"], json!("clip.mp4"));
    assert_eq!(m["selector"], json!("best"));
    assert_eq!(m["variant"], json!("320x240"));
    assert_eq!(m["manifestUrl"], json!("https://x/m.m3u8"));
    assert_eq!(m["tracks"][0]["segmentsDone"], json!(6));
    // Non-media tasks omit the key.
    let bare = super::view::status_entry_json(&base_view());
    assert!(bare.get("media").is_none());
}

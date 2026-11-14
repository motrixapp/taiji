//! Session method execution: parameter decoding -> SessionCommand
//! construction -> session round trip -> reply mapping (moved verbatim
//! from dispatch.rs; only visibility widened to pub(crate)).
//!
//! The command-construction branches for the 35 aria2 methods and the
//! `taiji.*` extensions live here (method-name routing and parameter
//! validation semantics are frozen; the routing category = the core
//! [`RpcMethodKind`] descriptor):
//! - immediate-semantics commands (shutdown/forceShutdown thread through
//!   to shutdown; addMetalink executes at the [`crate::metalink`]
//!   consumption seam — parse -> per-task AddUri expansion;
//!   `taiji.createTorrent` calls the `taiji_core::create` facade
//!   directly);
//! - the query families (tellStatus/tellActive/tellWaiting/tellStopped/
//!   getFiles/getPeers/getServers/getUris/getOption) run through the
//!   [`QUERY_METHODS`] table-driven loop: the entry closures carry the
//!   decode shape / command construction / reply rendering, with keys
//!   and pagination semantics unchanged;
//! - the remaining methods decode and send a SessionCommand; replies
//!   are normalized to aria2 JSON by [`super::view::encode_reply`].
//!
//! Upstream anchor mapping: docs/design/rpc.md

use serde_json::{Value, json};
use std::path::PathBuf;
use tracing::info;

use taiji_core::create::{
    CreateOutput, CreateTorrentParams, DEFAULT_PIECE_LENGTH, TorrentForm, create_torrent,
};
use taiji_core::session::{CommandReply, OffsetMode, RpcMethodKind, SessionCommand};

use crate::aria2::error::{
    MSG_FILE_PATHS_NOT_PROVIDED as E_MSG_FILE_PATHS,
    MSG_ILLEGAL_ARGUMENT as E_MSG_ILLEGAL_ARGUMENT, MSG_INTEGER_GE_ONE as E_MSG_INTEGER_GE_ONE,
    MSG_TORRENT_NOT_BASE64 as E_MSG_TORRENT_NOT_BASE64,
    MSG_TRACKER_URLS_NOT_PROVIDED as E_MSG_TRACKER_URLS,
    MSG_URI_NOT_PROVIDED as E_MSG_URI_NOT_PROVIDED, MSG_URL_NOT_PROVIDED as E_MSG_URL_NOT_PROVIDED,
    RpcError, map_create_torrent_error, map_session_error,
};
use crate::base64;
use crate::jsonrpc::RpcResponse;

use super::AppState;
use super::params::{
    gid_param, opt_keys, opt_options, opt_position, param_error, required, required_i64,
    required_num, string_list, try_rpc, uint_param, uint_value,
};
use super::view::{
    apply_keys, created_torrent_json, encode_reply, file_entry_json, num_clamp, peer_entry_json,
    render_status_list, server_entry_json, status_entry_json, unexpected_reply,
};

/// `taiji.createTorrent` execution (the taiji.* namespace; a write
/// face — already rejected by the dispatch-layer write gate when
/// `--rpc-secret` is unset). Parameter surface (positional):
///
/// `createTorrent(files, outputDir, options?)`
///
/// - `files`: explicit disk path strings (>=1). No directory recursion
///   (the caller enumerates — the creator input model is an explicit
///   file list); in-torrent relative paths and the torrent name are
///   derived by the core facade from the common parent directory
///   (single file = the file name).
/// - `outputDir`: the output directory (aria2 style; the product is
///   `<derived-name>.torrent`, overwriting same names; the directory
///   must exist).
/// - `options` (optional dict, camelCase like the taiji.* face):
/// - `pieceLength`: a number or numeric string, bytes (a power of two
///   and >=16KiB; default 16384 — the BEP52 floor, the same value as
///   the libtorrent automatic floor in `create_torrent.cpp`; an
///   engine freedom: aria2 has no createTorrent to cross-check
///   against);
/// - `format`: "v1"|"v2"|"hybrid" (default "hybrid" — with
///   libtorrent's default flags both hash sets are present, i.e.
///   hybrid, `create_torrent.hpp`);
/// - `private`: bool or "true"/"false" (BEP27);
/// - `comment`: a string;
/// - `announce`: a string or string array (1 = the top-level
///   announce; >=2 = announce + announce-list with each entry its
///   own tier, BEP12);
/// - `creationDate`: unix seconds (omitted by default — libtorrent's
///   default writes the current time, `create_torrent.cpp`;
///   omitting here keeps identical material byte-identical).
///
/// Synchronous return: success = written to disk + a reply with output/
/// name/format/pieceLength/totalLength/infohashV1/infohashV2 (the
/// infohash carried per form: v1-only has no v2 identity, v2-only no
/// v1 identity). Hashing large files is blocking: the kernel
/// read-and-hash runs in spawn_blocking, under the outer 600s timeout
/// ceiling (no synchronous RPC without a timeout cap); timeout =
/// `taiji.create_torrent.timeout`.
///
/// Does not go through the SessionActor: torrent creation has no
/// session state, and the single-threaded actor must not be blocked by
/// minute-scale hashing — the `taiji_core::create` facade is called
/// directly (core only supplies semantics; error mapping stays in the
/// rpc error table).
async fn create_torrent_method(st: &AppState, params: &[Value], id: Value) -> RpcResponse {
    let _ = st; // no session state consumed; signature matches the dispatch face (auth/write gate already done there).
    let files = try_rpc!(id, string_list(params, 0));
    if files.is_empty() {
        // Same shape as aria2 addUri's empty-set message (RpcMethodImpl.cc).
        return RpcResponse::error(&RpcError::generic(E_MSG_FILE_PATHS), id);
    }
    let output_dir = match required(params, 1) {
        Err(e) => return RpcResponse::error(&e, id),
        Ok(v) => v,
    };
    let dir = match output_dir.as_str() {
        Some(s) => PathBuf::from(s),
        None => return RpcResponse::error(&param_error(1, false), id),
    };

    // options dict (explicit null/absent = all defaults; non-object = a type error).
    let options = match params.get(2) {
        None | Some(Value::Null) => serde_json::Map::new(),
        Some(Value::Object(m)) => m.clone(),
        Some(_) => return RpcResponse::error(&param_error(2, false), id),
    };
    let get = |k: &str| options.get(k).filter(|v| !v.is_null());

    let piece_length = match get("pieceLength") {
        None => DEFAULT_PIECE_LENGTH,
        Some(v) => match uint_value(v, 2, u32::MAX as u64) {
            Err(e) => return RpcResponse::error(&e, id),
            Ok(n) => n as u32,
        },
    };
    let format = match get("format") {
        None => TorrentForm::Hybrid,
        Some(Value::String(s)) => match s.as_str() {
            "v1" => TorrentForm::V1Only,
            "v2" => TorrentForm::V2Only,
            "hybrid" => TorrentForm::Hybrid,
            other => {
                return RpcResponse::error(&RpcError::unknown_torrent_format(other), id);
            }
        },
        Some(_) => return RpcResponse::error(&param_error(2, false), id),
    };
    let private = match get("private") {
        None => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => match s.as_str() {
            "true" => true,
            "false" => false,
            _ => return RpcResponse::error(&param_error(2, false), id),
        },
        Some(_) => return RpcResponse::error(&param_error(2, false), id),
    };
    let comment = match get("comment") {
        None => None,
        Some(Value::String(s)) => Some(s.clone()),
        Some(_) => return RpcResponse::error(&param_error(2, false), id),
    };
    let announce = match get("announce") {
        None => Vec::new(),
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Array(items)) => {
            let urls: Vec<String> = items
                .iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect();
            urls
        }
        Some(_) => return RpcResponse::error(&param_error(2, false), id),
    };
    let creation_date = match get("creationDate") {
        None => None,
        Some(Value::Number(n)) => match n.as_i64() {
            Some(i) => Some(i),
            None => return RpcResponse::error(&param_error(2, false), id),
        },
        Some(Value::String(s)) => match s.trim().parse::<i64>() {
            Ok(i) => Some(i),
            Err(_) => return RpcResponse::error(&param_error(2, false), id),
        },
        Some(_) => return RpcResponse::error(&param_error(2, false), id),
    };

    let created = create_torrent(CreateTorrentParams {
        files: files.iter().map(PathBuf::from).collect(),
        output: CreateOutput::Dir(dir),
        piece_length,
        form: format,
        private,
        comment,
        announce,
        creation_date,
    })
    .await;
    match created {
        Ok(info) => {
            info!(
                target: "taiji::rpc::dispatch",
                output = %info.output.display(),
                format = info.format_name(),
                total_length = info.total_length,
                "rpc createTorrent completed"
            );
            RpcResponse::ok(created_torrent_json(&info), id)
        }
        Err(e) => RpcResponse::error(&map_create_torrent_error(&e), id),
    }
}

// ---- Query families: table-driven dispatch (the routing-category
// single point = the core [`RpcMethodKind`] descriptor) ----

/// Query-family decode product (the union of the family's parameter
/// positions; the shape enum guarantees unused fields are not consumed
/// — defaults are placeholders only).
#[derive(Default)]
struct QueryParams {
    /// The gid locator (GidKeys/GidOnly shapes).
    gid: String,
    /// The keys filter (GidKeys/KeysOnly/PagedKeys shapes; empty = all fields).
    keys: Vec<String>,
    /// The pagination offset (raw i64; negative = counting from the
    /// tail, reversed at rendering).
    offset: i64,
    /// The pagination num (raw i64; command construction clamps to the
    /// u32 payload via `num_clamp`, rendering uses the raw value — both
    /// accounting points of the original branch, kept verbatim).
    num: i64,
}

/// Query-family parameter decode shapes (aria2 parameter positions; the
/// correspondence to the core categories = QueryList in {KeysOnly,
/// PagedKeys}, QueryStatus in {GidKeys, GidOnly} — locked by governance
/// tests). The decode order follows the original branch verbatim (the
/// error priority unchanged).
#[derive(Debug, Clone, Copy)]
pub(crate) enum QueryShape {
    /// (gid, keys) — tellStatus.
    GidKeys,
    /// (keys) — tellActive.
    KeysOnly,
    /// (offset, num, keys) — tellWaiting/tellStopped.
    PagedKeys,
    /// (gid) — getFiles/getPeers/getServers/getUris/getOption.
    GidOnly,
}

/// Query-family entry: method name + core category + decode shape +
/// command-construction closure + reply-render closure. All closures
/// are non-capturing fns (the table is statically constructible);
/// rendering carries a mismatched reply back as `Err(other)` — the
/// defensive face (unexpected_reply) wording matches the original
/// branch verbatim.
#[derive(Debug)]
pub(crate) struct QueryEntry {
    /// The canonical method name (literally the core descriptor `name`).
    pub(crate) name: &'static str,
    /// The core descriptor category projection (governance tests lock
    /// same names/categories/order).
    pub(crate) kind: RpcMethodKind,
    /// The parameter decode shape ([`QueryShape`]).
    pub(crate) shape: QueryShape,
    /// Command construction (decoded product -> SessionCommand).
    build: fn(&QueryParams) -> SessionCommand,
    /// Reply rendering (CommandReply + decoded product -> JSON; `Err` =
    /// a reply-variant mismatch, carried to unexpected_reply with the
    /// original reply).
    render: fn(CommandReply, &QueryParams) -> Result<Value, CommandReply>,
}

/// The query-face dispatch table: the nine methods tellStatus/
/// tellActive/tellWaiting/tellStopped/getFiles/getPeers/getServers/
/// getUris/getOption (the keys/pagination/reply-rendering skeleton
/// shared by the family). Entry order follows the family order in the
/// core descriptor table — governance tests lock both tables to the
/// same names, categories, and order; adding a query method = give the
/// core descriptor a query category and add an entry here; missing
/// either fails.
pub(crate) const QUERY_METHODS: &[QueryEntry] = &[
    QueryEntry {
        name: "tellStatus",
        kind: RpcMethodKind::QueryStatus,
        shape: QueryShape::GidKeys,
        build: |p| SessionCommand::TellStatus {
            gid: p.gid.clone(),
            keys: p.keys.clone(),
        },
        render: |reply, p| match reply {
            CommandReply::TorrentStatus(v) => Ok(apply_keys(status_entry_json(&v), &p.keys)),
            other => Err(other),
        },
    },
    QueryEntry {
        name: "getFiles",
        kind: RpcMethodKind::QueryStatus,
        shape: QueryShape::GidOnly,
        build: |p| SessionCommand::GetFiles { gid: p.gid.clone() },
        render: |reply, _| match reply {
            CommandReply::Files(files) => {
                Ok(Value::Array(files.iter().map(file_entry_json).collect()))
            }
            other => Err(other),
        },
    },
    QueryEntry {
        name: "getPeers",
        kind: RpcMethodKind::QueryStatus,
        shape: QueryShape::GidOnly,
        build: |p| SessionCommand::GetPeers { gid: p.gid.clone() },
        render: |reply, _| match reply {
            CommandReply::Peers(peers) => {
                Ok(Value::Array(peers.iter().map(peer_entry_json).collect()))
            }
            other => Err(other),
        },
    },
    QueryEntry {
        name: "getServers",
        kind: RpcMethodKind::QueryStatus,
        shape: QueryShape::GidOnly,
        build: |p| SessionCommand::GetServers { gid: p.gid.clone() },
        render: |reply, _| match reply {
            CommandReply::Servers(servers) => {
                // The outer structure keeps the aria2 `{index, servers}`
                // nesting (single-file accounting); server entries use
                // the tracker-view fields.
                Ok(json!([{
                    "index": "1",
                    "servers": servers.iter().map(server_entry_json).collect::<Vec<_>>(),
                }]))
            }
            other => Err(other),
        },
    },
    QueryEntry {
        name: "getUris",
        kind: RpcMethodKind::QueryStatus,
        shape: QueryShape::GidOnly,
        build: |p| SessionCommand::GetUris { gid: p.gid.clone() },
        render: |reply, _| {
            match reply {
            CommandReply::Uris(uris) => Ok(Value::Array(
                uris.iter()
                    .map(|u| {
                        json!({ "uri": u.uri, "status": crate::aria2::status::uri_status_word(u.status) })
                    })
                    .collect(),
            )),
            other => Err(other),
        }
        },
    },
    QueryEntry {
        name: "getOption",
        kind: RpcMethodKind::QueryStatus,
        shape: QueryShape::GidOnly,
        build: |p| SessionCommand::GetOption { gid: p.gid.clone() },
        // Reply rendering = an encode_reply pass-through (an Options
        // dict — the original command face's shape; no in-family
        // unexpected defensive arm — the reply-variant contract is
        // guaranteed by the actor).
        render: |reply, _| encode_reply(reply),
    },
    QueryEntry {
        name: "tellActive",
        kind: RpcMethodKind::QueryList,
        shape: QueryShape::KeysOnly,
        build: |p| SessionCommand::TellActive {
            keys: p.keys.clone(),
        },
        render: |reply, p| match reply {
            CommandReply::StatusList(views) => Ok(render_status_list(views, None, None, &p.keys)),
            other => Err(other),
        },
    },
    QueryEntry {
        name: "tellWaiting",
        kind: RpcMethodKind::QueryList,
        shape: QueryShape::PagedKeys,
        build: |p| SessionCommand::TellWaiting {
            offset: p.offset,
            num: num_clamp(p.num),
            keys: p.keys.clone(),
        },
        render: |reply, p| match reply {
            CommandReply::StatusList(views) => Ok(render_status_list(
                views,
                Some(p.offset),
                Some(p.num),
                &p.keys,
            )),
            other => Err(other),
        },
    },
    QueryEntry {
        name: "tellStopped",
        kind: RpcMethodKind::QueryList,
        shape: QueryShape::PagedKeys,
        build: |p| SessionCommand::TellStopped {
            offset: p.offset,
            num: num_clamp(p.num),
            keys: p.keys.clone(),
        },
        render: |reply, p| match reply {
            CommandReply::StatusList(views) => Ok(render_status_list(
                views,
                Some(p.offset),
                Some(p.num),
                &p.keys,
            )),
            other => Err(other),
        },
    },
];

/// Query-family parameter decoding (a single point via the shape enum;
/// the decode order = the original branch order, error wording/priority
/// preserved verbatim).
fn decode_query_params(entry: &QueryEntry, params: &[Value]) -> Result<QueryParams, RpcError> {
    let mut p = QueryParams::default();
    match entry.shape {
        QueryShape::GidKeys => {
            p.gid = gid_param(params, 0)?;
            p.keys = opt_keys(params, 1)?;
        }
        QueryShape::KeysOnly => {
            p.keys = opt_keys(params, 0)?;
        }
        QueryShape::PagedKeys => {
            p.offset = required_i64(params, 0)?;
            p.num = required_num(params, 1)?;
            p.keys = opt_keys(params, 2)?;
        }
        QueryShape::GidOnly => {
            p.gid = gid_param(params, 0)?;
        }
    }
    Ok(p)
}

/// The query-family unified loop: decode -> command construction ->
/// session round trip -> reply rendering (the family skeleton's single
/// point; keys/pagination semantics unchanged inside the render
/// entries). Render `Err(other)` = a reply-variant mismatch ->
/// unexpected_reply (the original branch's wording).
async fn run_query_method(
    st: &AppState,
    entry: &QueryEntry,
    params: &[Value],
    id: Value,
) -> RpcResponse {
    // Routing invariant (a runtime defense line complementing the
    // governance tests): table entries must carry a query category — a
    // Control/Special entry here fails explicitly instead of routing
    // silently.
    debug_assert!(matches!(
        entry.kind,
        RpcMethodKind::QueryList | RpcMethodKind::QueryStatus
    ));
    let p = match decode_query_params(entry, params) {
        Ok(p) => p,
        Err(e) => return RpcResponse::error(&e, id),
    };
    let cmd = (entry.build)(&p);
    match st.session.call(cmd).await {
        Ok(reply) => match (entry.render)(reply, &p) {
            Ok(payload) => RpcResponse::ok(payload, id),
            Err(other) => unexpected_reply(entry.name, other, id),
        },
        Err(e) => RpcResponse::error(&map_session_error(&e), id),
    }
}

/// Query + method faces: parameter decoding -> SessionCommand -> reply
/// mapping (core semantic payloads -> aria2 JSON field names; the
/// query families' keys/pagination filtering runs inside the
/// table-driven loop).
pub(crate) async fn execute_session_method(
    st: &AppState,
    method: &'static str,
    params: Vec<Value>,
    id: Value,
) -> RpcResponse {
    // Immediate-semantics commands (shutdown threading / the RPC-layer
    // consumption seam / the direct facade call).
    match method {
        "shutdown" | "forceShutdown" => {
            let cmd = if method == "shutdown" {
                SessionCommand::Shutdown
            } else {
                SessionCommand::ForceShutdown
            };
            return match st.session.call(cmd).await {
                // Replies "OK" (createOKResponse: RpcMethodImpl.cc) and
                // cancels the server shutdown root — the CLI exits via
                // that token (a 1s budget).
                Ok(CommandReply::Accepted) => {
                    info!(
                        target: "taiji::rpc::dispatch",
                        via = method,
                        "rpc shutdown accepted; cancelling server token"
                    );
                    st.shutdown.cancel();
                    RpcResponse::ok(json!("OK"), id)
                }
                Err(e) => RpcResponse::error(&map_session_error(&e), id),
                Ok(other) => {
                    RpcResponse::error(&RpcError::unexpected_reply("shutdown", &other), id)
                }
            };
        }
        "addMetalink" => {
            // The metalink consumption-seam execution (feature gate —
            // registration lives in the core registry; this arm compiles
            // only with the feature on; with it off the method does not
            // exist = the canonical_method unknown-method face). Parse ->
            // per-task AddUri expansion -> a plain GID array reply.
            #[cfg(feature = "metalink")]
            return crate::metalink::add_metalink_method(st, &params, id).await;
            #[cfg(not(feature = "metalink"))]
            unreachable!("addMetalink is not registered with the metalink feature off")
        }
        "taiji.createTorrent" => {
            return create_torrent_method(st, &params, id).await;
        }
        _ => {}
    }
    // The query families: the table-driven unified loop (entry closures
    // carry the decode shape / command construction / reply rendering;
    // keys and pagination semantics unchanged inside the render entries).
    if let Some(entry) = QUERY_METHODS.iter().find(|entry| entry.name == method) {
        return run_query_method(st, entry, &params, id).await;
    }
    // Per-method session calls (parameter decode errors short-circuit).
    let call = async {
        match method {
            "addUri" => {
                let uris = string_list(&params, 0)?;
                if uris.is_empty() {
                    // Per RpcMethodImpl.cc.
                    return Err(RpcError::generic(E_MSG_URI_NOT_PROVIDED));
                }
                let options = opt_options(&params, 1)?;
                // The option-name gate (observation: warn + count; the
                // wire behavior is the reference's ignore rule).
                crate::aria2::option::note_option_intake(&options, "addUri");
                let position = opt_position(&params, 2)?;
                Ok(SessionCommand::AddUri {
                    uris,
                    options,
                    position,
                })
            }
            "addTorrent" => {
                let raw = required(&params, 0)?
                    .as_str()
                    .ok_or_else(|| param_error(0, false))?;
                let torrent = base64::decode(raw)
                    .ok_or_else(|| RpcError::generic(E_MSG_TORRENT_NOT_BASE64))?;
                // Param 1 = webseed URIs (kept in the aria2 shape; the
                // Motrix frontend never sends it — always empty). BEP19
                // url-list parsing is wired (the webseed set is projected
                // from the .torrent url-list); merging parameter URIs
                // into the webseed set is engine-side wiring — until then
                // they are explicitly dropped and declared.
                let _ = params.get(1);
                let options = opt_options(&params, 2)?;
                crate::aria2::option::note_option_intake(&options, "addTorrent");
                let position = opt_position(&params, 3)?;
                Ok(SessionCommand::AddTorrent {
                    torrent,
                    options,
                    position,
                })
            }
            "taiji.addUriWithCookies" => {
                // The addUriWithCookies fork: params = (uris, cookies,
                // options?, pos?) — cookies is a required array
                // (validated verbatim by parseRpcCookies, see
                // crate::rpc_cookies); options/pos reuse the addUri
                // template (an option-face subset — the derived arm
                // consumes like addUri). The http/https scheme gate is
                // backed by the actor's defensive arm (the fork's
                // same-position check, RpcMethodImpl.cc).
                let uris = string_list(&params, 0)?;
                if uris.is_empty() {
                    return Err(RpcError::generic(E_MSG_URI_NOT_PROVIDED));
                }
                let cookies = crate::rpc_cookies::parse_task_cookies(&params, 1)?;
                let options = opt_options(&params, 2)?;
                crate::aria2::option::note_option_intake(&options, "addUriWithCookies");
                let position = opt_position(&params, 3)?;
                Ok(SessionCommand::AddUriWithCookies {
                    uris,
                    cookies,
                    options,
                    position,
                })
            }
            "taiji.setTaskCookies" => {
                // The setTaskCookies fork: params = (gid, cookies). The
                // state gate / whole-set replacement / persistence order
                // live in the actor (the session arm).
                let gid = gid_param(&params, 0)?;
                let cookies = crate::rpc_cookies::parse_task_cookies(&params, 1)?;
                Ok(SessionCommand::SetTaskCookies { gid, cookies })
            }
            "pause"
            | "forcePause"
            | "unpause"
            // forceRecheck: disk recheck scheduling (taiji.forceRecheck
            // canonical / aria2.forceRecheck compat dual naming — the
            // canonical_method prefix-alias normalization converges both
            // names to this arm). Not in the upstream aria2/fork registry
            // (a capability extension).
            | "forceRecheck"
            | "remove"
            | "forceRemove"
            | "removeDownloadResult" => {
                let gid = gid_param(&params, 0)?;
                Ok(match method {
                    "pause" => SessionCommand::Pause { gid },
                    "forcePause" => SessionCommand::ForcePause { gid },
                    "unpause" => SessionCommand::Unpause { gid },
                    "forceRecheck" => SessionCommand::ForceRecheck { gid },
                    "remove" => SessionCommand::Remove { gid },
                    "forceRemove" => SessionCommand::ForceRemove { gid },
                    _ => SessionCommand::RemoveDownloadResult { gid },
                })
            }
            "pauseAll" => Ok(SessionCommand::PauseAll),
            // forcePauseAll: a no-parameter direct mapping (the reference
            // ForcePauseAllRpcMethod, RpcMethodImpl.cc; extra parameters
            // loosely ignored, same rule). The force difference follows
            // the single-task pause/forcePause equivalence and is carried
            // in the session arm (the actor's PauseAll shares the arm).
            "forcePauseAll" => Ok(SessionCommand::ForcePauseAll),
            "unpauseAll" => Ok(SessionCommand::UnpauseAll),
            "purgeDownloadResult" => Ok(SessionCommand::PurgeDownloadResult),
            "changeUri" => {
                let gid = gid_param(&params, 0)?;
                // Param 1 = fileIndex (1-based file-entry order,
                // RpcMethodImpl.cc checkRequiredInteger(req, 1,
                // IntegerGE(1))): a >=1 integer check + the value
                // forwarded (the file-entry domain check runs actor-side
                // against the task shape — the RpcMethodImpl.cc wording).
                let file_index = match params.get(1) {
                    None | Some(Value::Null) => return Err(param_error(1, true)),
                    Some(Value::Number(n)) => match n.as_i64() {
                        Some(i) if i >= 1 => i as u64,
                        _ => {
                            return Err(RpcError::generic(E_MSG_INTEGER_GE_ONE));
                        }
                    },
                    Some(_) => return Err(param_error(1, false)),
                };
                let del_uris = string_list(&params, 2)?;
                let add_uris = string_list(&params, 3)?;
                let pos = opt_position(&params, 4)?;
                Ok(SessionCommand::ChangeUri {
                    gid,
                    file_index,
                    del_uris,
                    add_uris,
                    pos,
                })
            }
            "taiji.getTorrentMetadata" => Ok(SessionCommand::GetTorrentMetadata { gid: gid_param(&params, 0)? }),
            "taiji.confirmTorrentSelection" => Ok(SessionCommand::ConfirmTorrentSelection { gid: gid_param(&params, 0)?, options: opt_options(&params, 1)? }),
            "taiji.getHttpOutput" => Ok(SessionCommand::GetHttpOutput { gid: gid_param(&params, 0)? }),
            "taiji.finalizeHttp" => {
                let gid = gid_param(&params, 0)?;
                let options = opt_options(&params, 1)?;
                let action = options.get("action").cloned().unwrap_or_else(|| "publish".into());
                Ok(SessionCommand::FinalizeHttp { gid, action, path: options.get("path").cloned() })
            }
            "changeOption" => {
                let gid = gid_param(&params, 0)?;
                if params.get(1).is_none() {
                    return Err(param_error(1, true));
                }
                let options = opt_options(&params, 1)?;
                crate::aria2::option::note_option_intake(&options, "changeOption");
                Ok(SessionCommand::ChangeOption { gid, options })
            }
            "taiji.addTracker" | "taiji.removeTracker" => {
                // Dynamic tracker editing (the taiji.* extension
                // namespace, camelCase; the compat face projects no
                // aria2.* aliases — the fork has no such methods, the
                // literal names exist in both states). Parameter surface
                // (positional): addTracker(gid, urls[, options]);
                // removeTracker(gid, urls).
                // - `urls`: a single string or string array (>=1;
                // non-string elements dropped like aria2's extractUris)
                // — both forms accepted (the aria2 addUri single-URI
                // scalar convention);
                // - addTracker `options.position`: an integer or numeric
                // string (both aria2 JSON numeric conventions), the
                // insertion tier position (0-based, clamped to the tail
                // when out of range); absent/Null = append to the tail.
                // An empty set = an explicit error ("tracker URLs are not
                // provided." — the addUri empty-set wording style; aria2
                // has no such methods, so there is no reference wording
                // to copy). GID-prefix resolution and shape gates live in
                // the actor (resolve_gid like the taiji.set* family).
                let gid = gid_param(&params, 0)?;
                let urls = match required(&params, 1)? {
                    Value::String(s) => vec![s.clone()],
                    Value::Array(items) => items
                        .iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect(),
                    _ => return Err(param_error(1, false)),
                };
                if urls.is_empty() {
                    return Err(RpcError::generic(E_MSG_TRACKER_URLS));
                }
                if method == "taiji.removeTracker" {
                    return Ok(SessionCommand::RemoveTracker { gid, urls });
                }
                let position = match params.get(2) {
                    None | Some(Value::Null) => None,
                    Some(Value::Object(map)) => match map.get("position") {
                        None | Some(Value::Null) => None,
                        Some(v) => Some(uint_value(v, 2, u64::MAX)? as usize),
                    },
                    Some(_) => return Err(param_error(2, false)),
                };
                Ok(SessionCommand::AddTracker {
                    gid,
                    urls,
                    position,
                })
            }
            "changePosition" => {
                // Parameter surface (gid, pos:int, how:string) — the
                // three-parameter type-check wording follows the
                // checkRequiredParam template (RpcMethodImpl.cc); the how
                // value domain {POS_SET, POS_CUR, POS_END} is closed at
                // this layer, other values get the verbatim "Illegal
                // argument." wording. Note: the reference parses str2Gid
                // before checking how; here gid resolution happens in the
                // actor (expandUnique needs the full GID set) — so with
                // both gid and how invalid, the wording priority is
                // inverted vs upstream; a parameter-combination edge
                // recorded in the declared differences (behavior
                // unchanged).
                let gid = gid_param(&params, 0)?;
                let pos = required_i64(&params, 1)?;
                let how = match required(&params, 2)?.as_str() {
                    Some("POS_SET") => OffsetMode::Set,
                    Some("POS_CUR") => OffsetMode::Cur,
                    Some("POS_END") => OffsetMode::End,
                    Some(_) => return Err(RpcError::generic(E_MSG_ILLEGAL_ARGUMENT)),
                    // A non-JSON-string = a type error (checkRequiredParam<String>).
                    None => return Err(param_error(2, false)),
                };
                Ok(SessionCommand::ChangePosition { gid, pos, how })
            }
            "changeGlobalOption" => {
                if matches!(params.first(), None | Some(Value::Null)) {
                    return Err(param_error(0, true));
                }
                let options = opt_options(&params, 0)?;
                crate::aria2::option::note_option_intake(&options, "changeGlobalOption");
                Ok(SessionCommand::ChangeGlobalOption { options })
            }
            "getGlobalOption" => Ok(SessionCommand::GetGlobalOption),
            // getVersion/getGlobalStat: parameterless reads pass through
            // (the encode_reply rendering matches the original branches
            // verbatim — the single source for Version/enabledFeatures
            // and the GlobalStat dict is the view module).
            "getVersion" => Ok(SessionCommand::GetVersion),
            "getGlobalStat" => Ok(SessionCommand::GetGlobalStat),
            "getSessionInfo" => Ok(SessionCommand::GetSessionInfo),
            "saveSession" => Ok(SessionCommand::SaveSession),
            "taiji.moveStorage" | "taiji.renameFile" => {
                // Extensions kept as an explicit not_supported face (not
                // in the committed set; the actor always answers
                // NotSupported after GID pre-resolution). Without these
                // arms the methods fell into an unreachable! panic (no
                // response) — the listMethods promise face diverging from
                // the callable face.
                let gid = gid_param(&params, 0)?;
                if method == "taiji.moveStorage" {
                    let Some(Value::String(dir)) = params.get(1) else {
                        return Err(param_error(1, true));
                    };
                    Ok(SessionCommand::MoveStorage {
                        gid,
                        dir: dir.clone(),
                    })
                } else {
                    let old_path = match params.get(1) {
                        Some(Value::String(s)) => s.clone(),
                        _ => return Err(param_error(1, true)),
                    };
                    let new_path = match params.get(2) {
                        Some(Value::String(s)) => s.clone(),
                        _ => return Err(param_error(2, true)),
                    };
                    Ok(SessionCommand::RenameFile {
                        gid,
                        old_path,
                        new_path,
                    })
                }
            }
            "taiji.banAddr" | "taiji.unbanAddr" | "taiji.listBans" => {
                // The three ban extensions (the taiji.* namespace; no
                // overlap with the aria2 method face or error codes).
                // banAddr(target[, minutes]): target = a single IP /
                // CIDR; minutes = the ban duration (a Number or numeric
                // string — both aria2 JSON forms), absent = permanent.
                // unbanAddr(target). listBans() takes no parameters
                // (extra parameters ignored — the aria2 lax rule).
                if method == "taiji.listBans" {
                    return Ok(SessionCommand::ListBans);
                }
                let target = required(&params, 0)?
                    .as_str()
                    .ok_or_else(|| param_error(0, false))?
                    .to_string();
                if method == "taiji.unbanAddr" {
                    Ok(SessionCommand::UnbanAddr { target })
                } else {
                    let minutes = match params.get(1) {
                        None | Some(Value::Null) => None,
                        Some(Value::Number(n)) => {
                            Some(n.as_i64().ok_or_else(|| param_error(1, false))?)
                        }
                        Some(Value::String(s)) => {
                            Some(s.trim().parse::<i64>().map_err(|_| param_error(1, false))?)
                        }
                        Some(_) => return Err(param_error(1, false)),
                    };
                    Ok(SessionCommand::BanAddr { target, minutes })
                }
            }
            "taiji.setSchedulerPolicy" | "taiji.getSchedulerPolicy" => {
                // The scheduler-policy pair (the taiji.* namespace).
                // Shapes: get(gid); set(gid, policy) — policy = a policy
                // name string ("rarest_first" etc.) or a
                // `{"policy": name, ...}` object (a reserved parameter
                // form; only the policy key is consumed here). Unknown
                // names fail explicitly; all three policies are allowed.
                let gid = gid_param(&params, 0)?;
                if method == "taiji.getSchedulerPolicy" {
                    return Ok(SessionCommand::GetSchedulerPolicy { gid });
                }
                let shown = params.get(1).cloned().unwrap_or(Value::Null);
                if shown.is_null() {
                    return Err(param_error(1, true));
                }
                let name = match &shown {
                    Value::String(s) => Some(s.clone()),
                    Value::Object(map) => {
                        map.get("policy").and_then(|v| v.as_str()).map(String::from)
                    }
                    _ => None,
                };
                let policy = name
                    .as_deref()
                    .and_then(|n| n.parse::<taiji_core::engine::SchedulerPolicy>().ok())
                    .ok_or_else(|| {
                        let shown_str = match &shown {
                            Value::String(s) => s.as_str(),
                            other => &other.to_string(),
                        };
                        RpcError::unknown_scheduler_policy(shown_str)
                    })?;
                Ok(SessionCommand::SetSchedulerPolicy { gid, policy })
            }
            "taiji.setStreamingPlayhead" => {
                // Extension method (taiji.* namespace). Parameter surface
                // (positional): setStreamingPlayhead(gid, file, position,
                // bytes_per_sec?) — file = the client file order
                // (0-based); position = the byte offset in the file;
                // bytes_per_sec absent/Null = the engine default tier
                // (1MiB/s). Numeric parameters accept numbers or numeric
                // strings per the aria2 JSON convention (negatives /
                // non-integer strings = an explicit error). Advancing =
                // repeated calls. An explicit 0 is rejected: through the
                // engine's windowing (bps x 30 -> max(stride)) 0 silently
                // degenerates to a one-piece window, where neither "stop
                // playback" nor "default" is a sound reading; the default
                // semantics are carried by omitting the parameter / Null.
                let gid = gid_param(&params, 0)?;
                let file = uint_param(&params, 1, u32::MAX as u64)? as u32;
                let position = uint_param(&params, 2, u64::MAX)?;
                let bytes_per_sec = match params.get(3) {
                    None | Some(Value::Null) => None,
                    Some(v) => {
                        let bps = uint_value(v, 3, u64::MAX)?;
                        if bps == 0 {
                            return Err(RpcError::playhead_bps_zero());
                        }
                        Some(bps)
                    }
                };
                Ok(SessionCommand::SetStreamingPlayhead {
                    gid,
                    file,
                    position,
                    bytes_per_sec,
                })
            }
            "taiji.setFilePriority" => {
                // Extension method (taiji.* namespace; multi-level file
                // priority, aligned with the libtorrent prioritize_files
                // capability — the partial-update pairs form). Parameter
                // surface (positional): setFilePriority(gid, pairs) —
                // pairs = an array of {index, priority} objects (index is
                // 1-based client file order — the select-file/getFiles
                // anchor; priority in -1..=7: -1 skip / 0 normal / 1..7
                // high). Numbers accept numbers or numeric strings per
                // the aria2 JSON convention; an empty array / non-object
                // entries / missing keys / out-of-domain values = an
                // explicit error (the session re-validates — the rpc/core
                // error split follows the addTracker family).
                let gid = gid_param(&params, 0)?;
                let shown = params.get(1).cloned().unwrap_or(Value::Null);
                let Value::Array(entries) = &shown else {
                    return Err(param_error(1, true));
                };
                if entries.is_empty() {
                    return Err(RpcError::file_priority_pairs_empty());
                }
                let mut pairs: Vec<(u32, i8)> = Vec::with_capacity(entries.len());
                for (n, entry) in entries.iter().enumerate() {
                    let Value::Object(map) = entry else {
                        return Err(RpcError::file_priority_entry_not_object(n));
                    };
                    let index = match map.get("index") {
                        Some(v) => uint_value(v, 1, u32::MAX as u64)? as u32,
                        None => {
                            return Err(RpcError::file_priority_entry_misses_index(n));
                        }
                    };
                    let level = match map.get("priority") {
                        Some(v) => {
                            // The level may be negative (-1) — number/
                            // numeric-string dual form; out of the i8
                            // domain = an explicit error.
                            let raw = match v {
                                Value::Number(n) => n.as_i64(),
                                Value::String(s) => s.trim().parse::<i64>().ok(),
                                _ => None,
                            };
                            raw.filter(|q| (-1..=7).contains(q))
                        }
                        None => None,
                    };
                    let Some(level) = level else {
                        return Err(RpcError::file_priority_entry_bad_priority(n));
                    };
                    pairs.push((index, level as i8));
                }
                Ok(SessionCommand::SetFilePriority { gid, pairs })
            }
            "taiji.getDiskTier" | "taiji.setDiskTier" => {
                // The disk-tier pair (the taiji.* namespace camelCase).
                // Shapes: get(gid); set(gid, tier) — tier = a tier-name
                // string ("throughput"|"ssd-protect"|"hdd-sequential",
                // the DiskTier::NAMES value domain; case-insensitive like
                // the core parser). Unknown names fail explicitly (no
                // silent fallback to the default tier); prealloc affects
                // only new allocations (a documented accounting note on
                // the session/engine side).
                let gid = gid_param(&params, 0)?;
                if method == "taiji.getDiskTier" {
                    return Ok(SessionCommand::GetDiskTier { gid });
                }
                let name = match params.get(1) {
                    None | Some(Value::Null) => return Err(param_error(1, true)),
                    Some(Value::String(s)) => s.clone(),
                    Some(_) => return Err(param_error(1, false)),
                };
                let tier = name
                    .parse::<taiji_core::engine::DiskTier>()
                    .map_err(|_| {
                        RpcError::unknown_disk_tier(&name, taiji_core::engine::DiskTier::NAMES)
                    })?;
                Ok(SessionCommand::SetDiskTier { gid, tier })
            }
            "taiji.addMedia" => {
                // addMedia(url, options?, position?): the media task's
                // add face. `options` carries
                // dir/out/selector/subtitles/template/no-meta + the
                // media-* flag family + probe-token; `cookies` (the
                // structured direct pass) rides
                // options.cookies as a validated array (the
                // addUriWithCookies parse face). Classification is
                // Resolving's business — the reply is the GID.
                let url = match required(&params, 0)? {
                    Value::String(s) => s.clone(),
                    _ => return Err(param_error(0, false)),
                };
                if url.trim().is_empty() {
                    return Err(RpcError::generic(E_MSG_URL_NOT_PROVIDED));
                }
                let options = opt_options(&params, 1)?;
                crate::aria2::option::note_option_intake(&options, "addMedia");
                let cookies = match params.get(1) {
                    Some(Value::Object(m)) if m.contains_key("cookies") => {
                        let cookie_value = m.get("cookies").cloned().unwrap_or(Value::Null);
                        let sub = vec![cookie_value];
                        // parse_task_cookies reads position 1 of the
                        // synthetic array.
                        crate::rpc_cookies::parse_task_cookies(&sub, 0)?
                    }
                    _ => Vec::new(),
                };
                let position = opt_position(&params, 2)?;
                Ok(SessionCommand::AddMedia {
                    url,
                    options,
                    cookies,
                    position,
                })
            }
            "taiji.probeMedia" => {
                // probeMedia(url) — the probe action face (a write face
                // through the gate: no secret → fail-closed).
                let url = match required(&params, 0)? {
                    Value::String(s) => s.clone(),
                    _ => return Err(param_error(0, false)),
                };
                if url.trim().is_empty() {
                    return Err(RpcError::generic(E_MSG_URL_NOT_PROVIDED));
                }
                Ok(SessionCommand::ProbeMedia { url })
            }
            "taiji.getMediaFormats" => Ok(SessionCommand::GetMediaFormats {
                gid: gid_param(&params, 0)?,
            }),
            "taiji.stopRecording" => Ok(SessionCommand::StopRecording {
                gid: gid_param(&params, 0)?,
            }),
            "taiji.clearMediaArchive" => {
                // The destructive whole-table clear;
                // parameterless (extra params ignored, the aria2 lax
                // rule) — a write face through the gate.
                Ok(SessionCommand::ClearMediaArchive)
            }
            "taiji.getCapabilities" => {
                // Structured capability discovery (the taiji.* namespace;
                // a parameterless query face; schema_version=1 is fixed by
                // the render layer). Extra parameters ignored (the aria2
                // lax rule).
                Ok(SessionCommand::GetCapabilities)
            }
            _ => unreachable!("method surface is canonical_method-filtered"),
        }
    };
    match call.await {
        Err(e) => RpcResponse::error(&e, id),
        Ok(cmd) => match st.session.call(cmd).await {
            Ok(reply) => match encode_reply(reply) {
                Ok(v) => RpcResponse::ok(v, id),
                // Unknown CommandReply variant for this method face (the
                // encode_reply #[non_exhaustive] wildcard): the same
                // unexpected-reply defensive error as the query family.
                Err(other) => unexpected_reply(method, other, id),
            },
            Err(e) => RpcResponse::error(&map_session_error(&e), id),
        },
    }
}

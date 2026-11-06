//! aria2 JSON value surface: renders `CommandReply` (core semantic
//! payloads) into aria2-compatible JSON (moved verbatim from
//! dispatch.rs; visibility widened to `pub(crate)` for sibling reuse).
//!
//! Responsibilities and per-function anchors:
//! Upstream anchor mapping: docs/design/rpc.md
//!
//! Convention: numbers -> strings, booleans -> "true"/"false" (aria2
//! uitos convention); all pagination arithmetic is saturating (security
//! fix).

use serde_json::{Value, json};

use taiji_core::session::{CommandReply, TorrentStatusView};

use crate::error::RpcError;
use crate::jsonrpc::RpcResponse;

/// getVersion.enabledFeatures (shape cross-checked against aria2
/// RpcMethodImpl.cc: version + enabledFeatures list). Content lists only
/// what the engine actually provides (honesty rule):
/// - "Async DNS": tokio async resolution;
/// - "BitTorrent": v1/v2/hybrid peer wire (taiji-bt protocol surface);
/// - "HTTP"/"HTTPS": HTTP download base (rustls TLS surface);
/// - "GZip": identity negotiation + automatic decompression;
/// - "Metalink": metalink v4 parsing + addMetalink (feature-gated — the
/// compiled state is presented accurately; the whole name is absent
/// when the feature is off; new fields go into the difference
/// declaration, aria2 ENABLE_METALINK same name and shape).
///
/// FTP/FTPS/SFTP transport adapters are not listed — no overclaiming.
pub const ENABLED_FEATURES: &[&str] = &[
    "Async DNS",
    "BitTorrent",
    "HTTP",
    "HTTPS",
    "GZip",
    #[cfg(feature = "metalink")]
    "Metalink",
];

/// CommandReply (core semantics) -> aria2 JSON (field names / string
/// values cross-checked against aria2 RpcMethodImpl.cc: GID hex16,
/// length fields as string values, changeUri [del, add] integer list,
/// getSessionInfo sessionId dict). Query-side payloads (StatusList/
/// TorrentStatus/Files/...) are rendered by dedicated renderers and do
/// not pass through this function. `Err` = a reply variant this face
/// does not encode (a broken structural invariant — the same defensive
/// face as [`unexpected_reply`], never a faked payload).
pub(crate) fn encode_reply(reply: CommandReply) -> Result<Value, CommandReply> {
    match reply {
        CommandReply::Accepted => Ok(json!("OK")),
        CommandReply::Gid(g) => Ok(json!(g.to_string())),
        CommandReply::Version { version } => Ok(json!({
            "version": version,
            "enabledFeatures": ENABLED_FEATURES,
        })),
        // Defensive completeness: the StatusList normal path renders in
        // the query branch (keys/pagination).
        CommandReply::StatusList(views) => {
            Ok(Value::Array(views.iter().map(status_entry_json).collect()))
        }
        CommandReply::TorrentStatus(v) => Ok(status_entry_json(&v)),
        CommandReply::Files(files) => Ok(Value::Array(files.iter().map(file_entry_json).collect())),
        CommandReply::Peers(peers) => Ok(Value::Array(peers.iter().map(peer_entry_json).collect())),
        CommandReply::Servers(servers) => Ok(Value::Array(
            servers
                .iter()
                .map(server_entry_json)
                .map(|s| json!({ "index": "1", "servers": [s] }))
                .collect(),
        )),
        CommandReply::Uris(uris) => Ok(Value::Array(
            uris.iter()
                .map(|u| json!({"uri": u.uri, "status": u.status}))
                .collect(),
        )),
        CommandReply::GlobalStat(g) => Ok(json!({
            "downloadSpeed": g.download_speed.to_string(),
            "uploadSpeed": g.upload_speed.to_string(),
            "numActive": g.num_active.to_string(),
            "numWaiting": g.num_waiting.to_string(),
            "numStopped": g.num_stopped.to_string(),
            "numStoppedTotal": g.num_stopped_total.to_string(),
            // taiji extension keys (aria2's getGlobalStat has no such
            // keys): the four-pool in-flight
            // meters — the waiting FIFOs are NOT included (a waiting
            // breakdown rides the client-side tellWaiting status
            // histogram; the declaration face lands in the
            // rpc-api-diff entry).
            "numSeeding": g.num_seeding.to_string(),
            "numChecking": g.num_checking.to_string(),
            "numSynthesizing": g.num_synthesizing.to_string(),
        })),
        CommandReply::Options(map) => Ok(json!(map)),
        // taiji.probeMedia reply: the opaque token + the TTL the
        // server honors + the snapshot tree (the client sees what the
        // token maps to; the formats array is the format-node domain).
        CommandReply::MediaProbe {
            token,
            ttl_secs,
            formats,
        } => Ok(json!({
            "token": token,
            "expiresIn": ttl_secs,
            "url": formats.url,
            "kind": formats.kind,
            "formats": formats.formats.iter().map(format_node_json).collect::<Vec<_>>(),
        })),
        // taiji.getMediaFormats reply: the resolved tree (the same
        // node rendering).
        CommandReply::MediaFormats(tree) => Ok(json!({
            "url": tree.url,
            "kind": tree.kind,
            "formats": tree.formats.iter().map(format_node_json).collect::<Vec<_>>(),
        })),
        CommandReply::SessionInfo { session_id } => Ok(json!({ "sessionId": session_id })),
        CommandReply::UriChange { deleted, added } => Ok(json!([deleted, added])),
        // taiji.addTracker/removeTracker reply: a self-describing dict
        // (taiji.* extension style, same shape as getSchedulerPolicy/
        // getDiskTier — camelCase keys); the counts are the actual
        // mutation counts after dedup/miss removal, as bare integers
        // (same convention as the changeUri [del, add] Integer — a count
        // surface, not a length field, so no stringification).
        CommandReply::TrackerChange { removed, added } => {
            Ok(json!({ "removed": removed, "added": added }))
        }
        // taiji.clearMediaArchive reply: the removed-row
        // count in the extension's self-describing dict style.
        CommandReply::ArchiveCleared { removed } => Ok(json!({ "removed": removed })),
        // changePosition reply = bare integer (aria2 RpcMethodImpl.cc
        // `Integer::g(destPos)` — not stringified, unlike the
        // length-field family).
        CommandReply::Position { position } => Ok(json!(position)),
        // listBans: until stringified as a number (aria2 numeric
        // convention); permanent = "0" (aria2 "0 = unlimited" convention;
        // core-internal i64::MAX normalized at the RPC surface).
        CommandReply::Bans(bans) => Ok(Value::Array(
            bans.iter()
                .map(|b| {
                    json!({
                        "target": b.target,
                        "reason": b.reason,
                        "until": if b.until == i64::MAX {
                            "0".to_string()
                        } else {
                            b.until.to_string()
                        },
                        "source": b.source.as_str(),
                    })
                })
                .collect(),
        )),
        // getSchedulerPolicy: `{"policy": name}` object form (the params
        // side reserves room — params may be echoed here later without
        // changing the method shape).
        CommandReply::SchedulerPolicy { policy } => Ok(json!({ "policy": policy.name() })),
        // getDiskTier: `{"tier": name}` object form (same shape as
        // getSchedulerPolicy; the tier value space = DiskTier::NAMES,
        // same source as the config_json `disk_tier` value).
        CommandReply::DiskTier { tier } => Ok(json!({ "tier": tier.name() })),
        // getCapabilities: schema_version=1 structured capability
        // discovery (taiji.* extension surface, camelCase keys; the
        // payload is generated declaratively by the core policy/feature
        // registry — this function only fixes the JSON shape and keeps
        // no second list).
        CommandReply::Capabilities(c) => Ok(capabilities_json(&c)),
        // Forward-compat (CommandReply is #[non_exhaustive]): an unknown
        // future variant is carried back to the caller's unexpected-reply
        // error face, never encoded as a fake payload.
        other => Err(other),
    }
}

/// `taiji.getCapabilities` reply rendering (schema_version=1). Shape:
/// `scheduler{available,sessionDefault,perTaskOverride}`,
/// `diskPolicy{available,configOnly}`,
/// `features{name:{supported,enabled}}`, `protocol.bep` and
/// `rpcExtensions` — every field passes straight through from the core
/// view (single source of truth, see
/// `taiji_core::engine::capabilities`).
fn capabilities_json(c: &taiji_core::engine::CapabilitiesView) -> Value {
    let features: serde_json::Map<String, Value> = c
        .features
        .iter()
        .map(|f| {
            (
                f.name.to_string(),
                json!({ "supported": f.supported, "enabled": f.enabled }),
            )
        })
        .collect();
    json!({
        "schemaVersion": 1,
        "version": c.version,
        "scheduler": {
            "available": c.scheduler_available,
            "sessionDefault": c.scheduler_default,
            "perTaskOverride": c.scheduler_per_task_override,
        },
        "diskPolicy": {
            "available": c.disk_tiers,
            "configOnly": c.disk_config_only,
        },
        "features": Value::Object(features),
        "protocol": {
            "bep": c.beps,
        },
        "rpcExtensions": c.rpc_extensions,
        // taiji.* extension notification event names (recovery event
        // surface; the six aria2 names and the system.listNotifications
        // frozen table are unchanged — extension events are declared via
        // capabilities, per the taiji.* namespace policy).
        "notifications": c.notifications,
    })
}

/// `taiji.createTorrent` reply rendering (the taiji.* surface uses
/// camelCase uniformly). Numeric fields follow the aria2 stringification
/// convention; both infohashes are carried by shape (v1-only has no v2
/// identity, v2-only no v1 identity — the key is absent, no
/// overclaiming).
pub(crate) fn created_torrent_json(info: &taiji_core::create::CreatedTorrentInfo) -> Value {
    let mut d = serde_json::Map::new();
    d.insert("output".into(), json!(info.output.display().to_string()));
    d.insert("name".into(), json!(info.name));
    d.insert("format".into(), json!(info.format_name()));
    d.insert("pieceLength".into(), jnum(u64::from(info.piece_length)));
    d.insert("totalLength".into(), jnum(info.total_length));
    if let Some(h) = &info.info_hash_v1 {
        d.insert("infohashV1".into(), json!(jhex(h)));
    }
    if let Some(h) = &info.info_hash_v2 {
        d.insert("infohashV2".into(), json!(jhex(h)));
    }
    Value::Object(d)
}

/// Defense for query methods receiving an unexpected reply (a broken
/// structural invariant -> explicit error, never faked).
pub(crate) fn unexpected_reply(method: &str, other: CommandReply, id: Value) -> RpcResponse {
    RpcResponse::error(
        &RpcError::generic(format!("unexpected {method} reply: {other:?}")),
        id,
    )
}

// ---- aria2 JSON value surface (numbers -> strings, booleans -> "true"/"false") ----

fn jnum(n: u64) -> Value {
    json!(n.to_string())
}

fn jbool(v: bool) -> Value {
    json!(if v { "true" } else { "false" })
}

fn jhex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// peerId percent-encoding (direct translation of aria2 util.cc
/// `torrentPercentEncode`: alphanumerics kept, everything else as
/// uppercase %XX).
fn torrent_percent_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for &b in bytes {
        if b.is_ascii_alphanumeric() {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// tellStatus/tell* single view -> aria2 dict. Field set and presence
/// conditions branch by source: live (active/waiting/paused) =
/// gatherProgressCommon + gatherProgressBitTorrent (aria2
/// RpcMethodImpl.cc); stopped (error/complete/removed) =
/// gatherStoppedDownload (same file).
/// Note: aria2 has no downloadLength key (previously emitted in excess)
/// — this layer no longer outputs it.
pub(crate) fn status_entry_json(v: &TorrentStatusView) -> Value {
    let stopped = matches!(
        v.status,
        taiji_core::session::StatusKind::Error
            | taiji_core::session::StatusKind::Complete
            | taiji_core::session::StatusKind::Removed
    );
    let mut d = serde_json::Map::new();
    d.insert("gid".into(), json!(v.gid.to_string()));
    if stopped {
        // gatherStoppedDownload: errorCode/errorMessage always present.
        // The numeric surface goes per-code + per-subkind straight to the
        // mapping table: engine-side structured failures
        // (`error_engine`) render via the mapping table — the canonical
        // code's second dimension (status code / read-idle timeout)
        // flows through with the subkind (404 -> 3, read-idle -> 2,
        // etc.); without a structured code the core merged surface holds
        // (0/31/1). The mapping's single source is
        // [`crate::error::http_numeric_code`].
        let numeric = match &v.error_engine {
            Some(f) => {
                let kind = engine_kind(f.kind);
                let n = crate::error::http_numeric_code(&f.code, kind);
                if n < 0 { 0 } else { n as u64 }
            }
            None => v.error_code.unwrap_or(0),
        };
        d.insert("errorCode".into(), jnum(numeric));
        d.insert(
            "errorMessage".into(),
            json!(v.error_message.clone().unwrap_or_default()),
        );
    }
    d.insert("status".into(), json!(v.status.as_str()));
    if !v.followed_by.is_empty() {
        d.insert(
            "followedBy".into(),
            Value::Array(v.followed_by.iter().map(|g| json!(g.to_string())).collect()),
        );
    }
    if let Some(g) = v.following {
        d.insert("following".into(), json!(g.to_string()));
    }
    if let Some(g) = v.belongs_to {
        d.insert("belongsTo".into(), json!(g.to_string()));
    }
    d.insert(
        "files".into(),
        Value::Array(v.files.iter().map(file_entry_json).collect()),
    );
    d.insert("totalLength".into(), jnum(v.total_length));
    d.insert("completedLength".into(), jnum(v.completed_length));
    d.insert("uploadLength".into(), jnum(v.upload_length));
    // bitfield: None / empty = key absent (same rule as aria2
    // getBitfieldLength() > 0).
    if let Some(bf) = &v.bitfield
        && !bf.is_empty()
    {
        d.insert("bitfield".into(), json!(jhex(bf)));
    }
    d.insert("downloadSpeed".into(), jnum(v.download_speed));
    d.insert("uploadSpeed".into(), jnum(v.upload_speed));
    if let Some(ih) = &v.info_hash {
        d.insert("infoHash".into(), json!(jhex(ih)));
        // stopped: numSeeders appears only when infoHash is present and
        // is always "0" (same rule as aria2).
        if stopped {
            d.insert("numSeeders".into(), jnum(v.num_seeders));
        }
    }
    if !stopped {
        // live BT: numSeeders/seeder always present
        // (gatherProgressBitTorrent).
        d.insert("numSeeders".into(), jnum(v.num_seeders));
        if let Some(s) = v.seeder {
            d.insert("seeder".into(), jbool(s));
        }
    }
    d.insert("pieceLength".into(), jnum(u64::from(v.piece_length)));
    d.insert("numPieces".into(), jnum(v.num_pieces));
    d.insert("connections".into(), jnum(v.connections));
    d.insert("dir".into(), json!(v.dir));
    if let Some(bt) = &v.bittorrent {
        d.insert("bittorrent".into(), bittorrent_json(bt));
    }
    // HTTP task extra surface (the `http` sub-dict; None = key absent —
    // same rule as the bittorrent field).
    if let Some(http) = &v.http {
        d.insert("http".into(), http_json(http));
    }
    // Media task extra surface (the `media` sub-dict; None = key
    // absent — same rule as http/bittorrent).
    if let Some(media) = &v.media {
        d.insert("media".into(), media_json(media));
    }
    Value::Object(d)
}

/// One format-tree node's JSON (the format-node field domain; camelCase keys,
/// numbers as bare integers — count faces, never stringified).
fn format_node_json(f: &taiji_core::session::media::FormatNode) -> Value {
    json!({
        "formatId": f.format_id,
        "protocol": f.protocol,
        "ext": f.ext,
        "resolution": f.resolution,
        "fps": f.fps,
        "hdr": f.hdr,
        "vcodec": f.vcodec,
        "acodec": f.acodec,
        "tbr": f.tbr,
        "abr": f.abr,
        // The abr/vbr/tbr triple's third member (added later;
        // 0.3 value domain = 0).
        "vbr": f.vbr,
        "filesize": f.filesize,
        "language": f.language,
        "hasVideo": f.has_video,
        "hasAudio": f.has_audio,
        "uri": f.uri,
    })
}

/// The `media` sub-dictionary payload (the promised fields:
/// kind/phase/phaseDetail/tracks[]/staging slot/selector/variant).
pub(crate) fn media_json(m: &taiji_core::session::MediaView) -> Value {
    let mut d = serde_json::Map::new();
    d.insert("kind".into(), json!(m.kind));
    d.insert("phase".into(), json!(m.phase));
    if let Some(detail) = &m.phase_detail {
        d.insert("phaseDetail".into(), json!(detail));
    }
    d.insert(
        "tracks".into(),
        Value::Array(
            m.tracks
                .iter()
                .map(|t| {
                    json!({
                        "label": t.label,
                        "kind": t.kind,
                        "state": t.state,
                        "segmentsDone": t.segments_done,
                        "segmentsTotal": t.segments_total,
                    })
                })
                .collect(),
        ),
    );
    d.insert("stagingDir".into(), json!(m.staging_dir));
    if let Some(name) = &m.output_name {
        d.insert("outputName".into(), json!(name));
    }
    if let Some(sel) = &m.selector {
        d.insert("selector".into(), json!(sel));
    }
    if let Some(variant) = &m.variant {
        d.insert("variant".into(), json!(variant));
    }
    d.insert("manifestUrl".into(), json!(m.manifest_url));
    Value::Object(d)
}

/// core-side subkind dimension -> the mapping-table [`HttpFailureKind`]
/// (one-to-one enum correspondence; the mapping's single source remains
/// this crate's error table — core only carries semantics). pub(crate):
/// the production render chain (the error.rs variant sweep / per-code
/// dispatch pins in end-to-end tests) and the rendering layer share one
/// conversion; private test copies are forbidden (pairing drift turns
/// the check red).
pub(crate) fn engine_kind(
    k: taiji_core::session::EngineFailureKind,
) -> crate::error::HttpFailureKind {
    use taiji_core::session::EngineFailureKind as K;
    match k {
        K::Bare => crate::error::HttpFailureKind::Bare,
        K::Status(s) => crate::error::HttpFailureKind::Status(s),
        K::TransportTimeout => crate::error::HttpFailureKind::TransportTimeout,
    }
}

/// `http` sub-dict (promised fields: finalUrl/connections/
/// extentsActive/blocksDone/blocksTotal/encoding/renamePending/sources).
/// The taiji.* extension surface uses camelCase keys uniformly (same
/// decision as file_entry_json recoveryStatus); numbers follow the aria2
/// stringification convention and booleans "true"/"false" (in-dict
/// style matches the outer surface); encoding absent (identity /
/// unprobed) = key absent.
/// Difference declaration: this dict as a whole is a taiji extension
/// (aria2 has no such key — the diff is whitelisted against the
/// promised-field table).
fn http_json(h: &taiji_core::session::HttpView) -> Value {
    let mut d = serde_json::Map::new();
    d.insert("finalUrl".into(), json!(h.final_url));
    d.insert("connections".into(), jnum(h.connections));
    d.insert("extentsActive".into(), jnum(h.extents_active));
    d.insert("blocksDone".into(), jnum(h.blocks_done));
    d.insert("blocksTotal".into(), jnum(h.blocks_total));
    if let Some(enc) = &h.encoding {
        d.insert("encoding".into(), json!(enc));
    }
    d.insert("renamePending".into(), jbool(h.rename_pending));
    d.insert(
        "sources".into(),
        Value::Array(
            h.sources
                .iter()
                .map(|s| {
                    json!({
                        "url": s.url,
                        "rate": s.rate.to_string(),
                        "state": s.state,
                    })
                })
                .collect(),
        ),
    );
    Value::Object(d)
}

/// bittorrent sub-dict (the full gatherBitTorrentMetadata field set from
/// aria2 RpcMethodImpl.cc; beyond aria2: metaVersion/v2InfoHash/private;
/// None = key absent).
fn bittorrent_json(bt: &taiji_core::session::BittorrentView) -> Value {
    let mut d = serde_json::Map::new();
    if let Some(c) = &bt.comment
        && !c.is_empty()
    {
        d.insert("comment".into(), json!(c));
    }
    if let Some(cd) = bt.creation_date {
        // aria2 creationDate = Integer (a JSON number, not a string).
        d.insert("creationDate".into(), json!(cd));
    }
    if let Some(m) = bt.mode {
        d.insert("mode".into(), json!(m));
    }
    d.insert(
        "announceList".into(),
        Value::Array(
            bt.announce_list
                .iter()
                .map(|tier| Value::Array(tier.iter().map(|u| json!(u)).collect()))
                .collect(),
        ),
    );
    if let Some(name) = &bt.name {
        d.insert("info".into(), json!({ "name": name }));
    }
    // Fields beyond aria2 (taiji extension convention).
    if let Some(mv) = bt.meta_version {
        d.insert("metaVersion".into(), json!(i64::from(mv)));
    }
    if let Some(v2) = &bt.v2_info_hash {
        d.insert("v2InfoHash".into(), json!(jhex(v2)));
    }
    if let Some(p) = bt.private {
        d.insert("private".into(), jbool(p));
    }
    Value::Object(d)
}

/// getFiles/files single entry (createFileEntry field surface from aria2
/// RpcMethodImpl.cc; beyond aria2: piecesRoot/pieceSize/padding).
pub(crate) fn file_entry_json(f: &taiji_core::session::FileEntryView) -> Value {
    let mut d = serde_json::Map::new();
    d.insert("index".into(), jnum(f.index));
    d.insert("path".into(), json!(f.path));
    d.insert("selected".into(), jbool(f.selected));
    // Extension key: per-file multi-level priority (no aria2 key;
    // aligned with the libtorrent file_priority capability; value space
    // -1/0/1..7).
    d.insert("priority".into(), json!(f.priority));
    d.insert("length".into(), jnum(f.length));
    d.insert("completedLength".into(), jnum(f.completed_length));
    d.insert(
        "uris".into(),
        Value::Array(
            f.uris
                .iter()
                .map(|u| json!({"uri": u.uri, "status": u.status}))
                .collect(),
        ),
    );
    if let Some(root) = &f.pieces_root {
        d.insert("piecesRoot".into(), json!(jhex(root)));
    }
    d.insert("pieceSize".into(), jnum(u64::from(f.piece_size)));
    d.insert("padding".into(), jbool(f.padding));
    // Hash recovery projection: only files participating in a missing
    // layer carry the key (None = key absent). Value space
    // layer_missing|recovering|ready (a manager UI can show "waiting
    // for hash recovery"); camelCase key names follow the taiji.*
    // surface decision.
    if let Some(st) = f.recovery {
        d.insert("recoveryStatus".into(), json!(st));
    }
    Value::Object(d)
}

/// getPeers single entry (gatherPeer field surface from aria2
/// RpcMethodImpl.cc; transport/crypto are taiji additions; port
/// stringified, booleans stringified, same as aria2).
pub(crate) fn peer_entry_json(p: &taiji_core::session::PeerEntryView) -> Value {
    json!({
        "peerId": match &p.peer_id {
            Some(id) => torrent_percent_encode(id),
            None => String::new(),
        },
        "ip": p.ip,
        "port": p.port.to_string(),
        "bitfield": jhex(&p.bitfield),
        "amChoking": jbool(p.am_choking),
        "peerChoking": jbool(p.peer_choking),
        "downloadSpeed": p.download_speed.to_string(),
        "uploadSpeed": p.upload_speed.to_string(),
        "seeder": jbool(p.seeder),
        "transport": p.transport.as_str(),
        "crypto": p.crypto.as_str(),
    })
}

/// getServers server entry (tracker view: uri/tier/status + scrape
/// cache; the aria2 server field surface uri/currentUri/downloadSpeed is
/// kept — downloadSpeed: BT tracker snapshots have no live rate = "0";
/// HTTP sources = the per-source measured reading).
pub(crate) fn server_entry_json(s: &taiji_core::session::ServerEntryView) -> Value {
    let mut d = serde_json::Map::new();
    d.insert("uri".into(), json!(s.url));
    d.insert("currentUri".into(), json!(s.url));
    d.insert("downloadSpeed".into(), json!(s.download_speed.to_string()));
    d.insert("tier".into(), jnum(u64::try_from(s.tier).unwrap_or(0)));
    d.insert("status".into(), json!(s.status));
    if let Some(n) = s.seeds {
        d.insert("seeds".into(), jnum(n.unsigned_abs()));
    }
    if let Some(n) = s.leechers {
        d.insert("leechers".into(), jnum(n.unsigned_abs()));
    }
    Value::Object(d)
}

/// keys filter (empty = all fields; top-level keys only — same rule as
/// aria2 requested_key, RpcMethodImpl.cc).
pub(crate) fn apply_keys(entry: Value, keys: &[String]) -> Value {
    if keys.is_empty() {
        return entry;
    }
    match entry {
        Value::Object(map) => Value::Object(
            map.into_iter()
                .filter(|(k, _)| keys.iter().any(|key| key == k))
                .collect(),
        ),
        other => other,
    }
}

/// Pagination num (command-surface u32 payload; already validated by
/// IntegerGE(0), clamped conversion).
pub(crate) fn num_clamp(num: i64) -> u32 {
    u32::try_from(num).unwrap_or(u32::MAX)
}

/// Pagination interval (direct translation of aria2 getPaginationRange,
/// RpcMethodImpl.h): num<=0 -> empty; negative offset counts from the
/// tail (tempoffset = offset + size; offset then moves back num-1,
/// clamped to 0 with num shrunk); a positive offset past the end ->
/// empty. Returns the half-open interval (start, end).
/// Security fix: all arithmetic is saturating — offset/num are remote
/// i64 inputs; `offset + num` used to wrap negative at num=i64::MAX,
/// panicking on the `views[start..0]` slice (release wrap / debug
/// overflow panic — a remote DoS).
pub(crate) fn pagination_range(offset: i64, num: i64, size: i64) -> Option<(usize, usize)> {
    if num <= 0 {
        return None;
    }
    let mut offset = offset;
    let mut num = num;
    let size = size.max(0);
    if offset < 0 {
        let tempoffset = offset.saturating_add(size);
        if tempoffset < 0 {
            return None;
        }
        offset = tempoffset.saturating_sub(num - 1);
        if offset < 0 {
            offset = 0;
            num = tempoffset.saturating_add(1);
        }
    } else if size <= offset {
        return None;
    }
    let last = offset.saturating_add(num).min(size);
    Some((offset.max(0) as usize, last.max(0) as usize))
}

/// tell* list rendering: slice for pagination + reverse for negative
/// offset (direct translation of AbstractPaginationRpcMethod::process's
/// `if (offset < 0) reverse`, RpcMethodImpl.h) + per-entry keys
/// filtering. `offset/num = None` means no pagination (tellActive).
pub(crate) fn render_status_list(
    views: Vec<TorrentStatusView>,
    offset: Option<i64>,
    num: Option<i64>,
    keys: &[String],
) -> Value {
    let total = views.len() as i64;
    let sliced: Vec<&TorrentStatusView> = match (offset, num) {
        (Some(o), Some(n)) => match pagination_range(o, n, total) {
            None => Vec::new(),
            Some((start, end)) => views[start..end].iter().collect(),
        },
        _ => views.iter().collect(),
    };
    let mut items: Vec<Value> = sliced
        .into_iter()
        .map(|v| apply_keys(status_entry_json(v), keys))
        .collect();
    if offset.is_some_and(|o| o < 0) {
        items.reverse();
    }
    Value::Array(items)
}

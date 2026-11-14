//! Metalink data-plane consumption seam (feature `metalink`).
//!
//! `taiji-metalink` only turns format into model (v4 parsing, mirror
//! lists, hash intake, metaurl extraction); task orchestration and
//! downloading stay on the existing paths. This module is the crate's
//! single RPC-side consumption seam and hosts the addMetalink method:
//! parse -> expand into per-task [`SessionCommand::AddUri`] entries ->
//! return a plain array of GID strings (the aria2 shape,
//! `RpcMethodImpl.cc` `AddMetalinkRpcMethod::process`). Method
//! registration is gated through the `taiji-core/metalink` passthrough
//! (the [`crate::dispatch`] `canonical_method` central point is
//! unchanged); with the feature off the module does not compile,
//! taiji-metalink stays out of the dependency graph, and addMetalink is
//! absent from the registry (`tests/feature_gate.rs` pins both states).
//!
//! Error-code discipline: the `taiji.metalink.*` string codes are owned
//! by the [`crate::aria2::error`] mapping table (the repo-wide single source);
//! [`crate::aria2::error::map_metalink_error`] takes
//! [`taiji_metalink::MetalinkError`].
//!
//! Expansion semantics (document order; the produced order is the
//! addMetalink reply GID order) and the declared differences vs aria2:
//! docs/design/rpc.md.
//!
//! Upstream anchor mapping: docs/design/rpc.md

use std::collections::{BTreeMap, HashSet};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::task::spawn_blocking;
use tracing::warn;

use taiji_core::metainfo::TorrentIdentity;
use taiji_core::session::{CommandReply, SessionCommand, magnet_identity, windows_unsafe_basename};

use crate::aria2::error::{RpcError, STR_METALINK_TIMEOUT, map_metalink_error, map_session_error};
use crate::base64;
use crate::dispatch::params::{opt_options, opt_position, param_error, try_rpc};
use crate::jsonrpc::RpcResponse;

/// Parse budget ceiling (600s): the same discipline as
/// `taiji.createTorrent` — an explicit backstop for the ban on
/// synchronous RPCs without a timeout cap (the timeout only bounds the
/// reply, it does not cancel the underlying blocking parse;
/// cancellation semantics in the [`add_metalink_method`] fn doc).
const METALINK_PARSE_TIMEOUT: Duration = Duration::from_secs(600);

pub use taiji_metalink::{
    DEFAULT_PRIORITY, Hash, HashKind, MAX_DOCUMENT_BYTES, MAX_FILES, MAX_URLS_PER_FILE, MetaUrl,
    Metalink, MetalinkError, MetalinkFile, ParseWarning, PieceSet, Publisher, Signature, Url,
    VerifyError, WarningKind, parse,
};

// The metalink seam name tables live in the adapter option table
// (`crate::aria2::option`) — rpc-owned names, one home.
use crate::aria2::option::{AUTO_DISCOVER_OPTION, UNSUPPORTED_METALINK_OPTIONS};

/// One expansion product: (uris, options) ready for [`SessionCommand::AddUri`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddUriPlan {
    /// Source URIs (a single BT entry = 1; HTTP multi-mirror = all
    /// filtered mirrors, stably pre-sorted by priority ascending).
    pub uris: Vec<String>,
    /// Task options (the caller's base options + entry overrides; the
    /// caller's `out`/`checksum` keys are stripped at this seam).
    /// checksum can only be carried by HTTP plans (the entry's own
    /// six-hash-domain document declaration, sha-256 preferred); BT
    /// plans never carry out/checksum — the entry's `<hash>` declarations
    /// do not enter the BT face (BT integrity is decided by the fetched
    /// metadata's piece hashes).
    pub options: BTreeMap<String, String>,
}

/// Expansion decision: metalink document model -> AddUri plan sequence
/// (pure function; order = reply GID order, see the module doc). Shared
/// by the CLI `--metalink-file` and RPC addMetalink.
pub fn expand_add_uri_plans(doc: &Metalink, mut base: BTreeMap<String, String>) -> Vec<AddUriPlan> {
    // The caller's out/checksum never enter the metalink shape (single
    // strip point): `out` is always overridden by the entry name (BT
    // plans must not inherit the caller's out); `checksum` is produced
    // only when the entry itself declares a six-hash-domain document
    // hash — an entry without one inheriting an external checksum is a
    // fail-closed leak surface (healthy entries wedged by external
    // values).
    base.remove("out");
    base.remove("checksum");
    let mut plans = Vec::new();
    // Per-document metaurl dedup (by URI literal; the by-URL-grouping
    // rule of aria2 `groupEntryByMetaurlName` — the first occurrence
    // produces the BT task, later ones share it). HashSet: a linear Vec
    // degrades to O(n^2) for "many entries x repeated metaurls per
    // file".
    let mut seen_metaurls: HashSet<&str> = HashSet::new();
    // Per-document magnet identity dedup (by the btih/btmh id pair):
    // different spellings of the same torrent (any dn/tr variation) are
    // also rejected by the session add_uri identity_is_duplicate
    // decision — without absorption one benign duplicate would fail the
    // whole method halfway and kill every later entry. The two sets form
    // identities_overlap (v1 hit OR v2 hit), expanded exactly over all
    // previously seen identities (membership accumulates as registration
    // proceeds, so transitivity holds).
    let mut seen_bt_v1: HashSet<[u8; 20]> = HashSet::new();
    let mut seen_bt_v2: HashSet<[u8; 32]> = HashSet::new();
    // Per-document (dir,out) occupancy dedup (basename flatten
    // collisions): sub1/a.iso and sub2/a.iso (including duplicate
    // `<file name>` entries) flatten onto the same part file and would
    // co-write it under concurrent activation (silent corruption without
    // a checksum) — later entries skipped with a warning.
    let mut seen_outputs: HashSet<(String, String)> = HashSet::new();
    let dir_key = base.get("dir").cloned().unwrap_or_default();
    for file in &doc.files {
        // 1. metaurl direct BT conversion: examine candidates until the
        // first usable BT task is produced (first usable wins; same
        // direction as aria2's one torrentRg per metaurl group).
        // mediatype="torrent" is case-insensitive (RFC 5854 mediatype
        // text names carry IANA semantics); unusable candidates (a
        // non-torrent mediatype / a duplicate URI / neither magnet nor
        // .torrent) are skipped with a warning and later candidates are
        // still examined — an unusable first candidate no longer blocks
        // later usable ones in the same entry.
        for mu in &file.metaurls {
            if !mu.mediatype.eq_ignore_ascii_case("torrent") {
                warn!(
                    target: "taiji::rpc::metalink",
                    file = %file.name,
                    mediatype = %mu.mediatype,
                    "metaurl mediatype not supported; entry skipped (declared difference)"
                );
                continue;
            }
            if !seen_metaurls.insert(mu.uri.as_str()) {
                // The URI was already registered by an earlier candidate
                // (it produced a BT task or registered the unusable face)
                // — skip + warn (first wins; later candidates of this
                // entry are still examined).
                warn!(
                    target: "taiji::rpc::metalink",
                    file = %file.name,
                    uri = %taiji_core::redact::escape_control_chars(&mu.uri),
                    "metaurl already consumed by an earlier candidate; duplicate skipped \
                     (first occurrence wins)"
                );
                continue;
            }
            let Some(uri) = torrent_entry_uri(&mu.uri) else {
                warn!(
                    target: "taiji::rpc::metalink",
                    file = %file.name,
                    "metaurl is neither magnet nor a .torrent URL; direct BT \
                     conversion skipped (declared difference)"
                );
                continue;
            };
            if uri.starts_with("magnet:") {
                // magnet: identity resolution shares the session's
                // duplicate decision (core session magnet_identity). A
                // resolution failure is not swallowed here — the plan is
                // produced normally and the session's add_uri surfaces the
                // explicit error (the fn doc's failure semantics).
                if let Some(identity) = magnet_identity(&uri)
                    && duplicate_magnet_identity(&identity, &mut seen_bt_v1, &mut seen_bt_v2)
                {
                    warn!(
                        target: "taiji::rpc::metalink",
                        file = %file.name,
                        "magnet identity already seen in this document; duplicate metaurl \
                         skipped, later entries proceed (first occurrence wins)"
                    );
                    continue;
                }
            }
            plans.push(AddUriPlan {
                uris: vec![uri],
                // BT plan = the net face after caller-key stripping: no
                // out/checksum — the entry's `<hash>` declarations do not
                // enter the BT face (module-doc declared difference).
                options: base.clone(),
            });
            break;
        }
        // 2. HTTP multi-mirror task (zero usable mirrors = nothing
        // produced — the aria2 `resources.empty()` branch after
        // dropUnsupportedResource). Priority-ascending stable pre-sort
        // (1 = best; equal priorities keep document order — same
        // direction as aria2's InOrderURISelector priority pick).
        let mut mirrors: Vec<(u32, usize, String)> = file
            .urls
            .iter()
            .enumerate()
            .map(|(i, u)| (u.priority, i, u.uri.clone()))
            .filter(|(_, _, uri)| is_http_family_uri(uri))
            .collect();
        mirrors.sort_by_key(|(priority, order, _)| (*priority, *order));
        if mirrors.is_empty() {
            continue;
        }
        let Some(out) = entry_out_name(&file.name) else {
            warn!(
                target: "taiji::rpc::metalink",
                name = %file.name,
                "metalink file name does not fit the --out plain-name domain; \
                 entry skipped (declared difference)"
            );
            continue;
        };
        if !seen_outputs.insert((dir_key.clone(), out.clone())) {
            warn!(
                target: "taiji::rpc::metalink",
                name = %file.name,
                out = %out,
                "metalink entries flatten to the same (dir,out); duplicate \
                 entry skipped to avoid co-writing one part file"
            );
            continue;
        }
        let mut options = base.clone();
        options.insert("out".to_string(), out);
        // checksum: the entry's own `<hash>` declaration folded into the
        // `--checksum` domain (six hashes; the single-checksum form =
        // the strongest single declaration): sha-256 first, otherwise
        // the first in document order; no in-domain declaration = not
        // carried (the caller's value was stripped at this seam).
        if let Some(hash) = file
            .hashes
            .iter()
            .find(|h| matches!(h.kind(), HashKind::Sha256))
            .or_else(|| {
                file.hashes.iter().find(|h| {
                    matches!(
                        h.kind(),
                        HashKind::Md5
                            | HashKind::Sha1
                            | HashKind::Sha224
                            | HashKind::Sha384
                            | HashKind::Sha512
                    )
                })
            })
        {
            options.insert(
                "checksum".to_string(),
                format!("{}={}", hash.kind().type_name(), hash.hex()),
            );
        }
        plans.push(AddUriPlan {
            uris: mirrors.into_iter().map(|(_, _, uri)| uri).collect(),
            options,
        });
    }
    plans
}

/// Magnet identity registration check: a hit on either id against the
/// previously seen sets = a same-document duplicate (the set form of the
/// session `identities_overlap` v1-OR-v2 criterion); both sets must be
/// registered (a hybrid magnet's dual xt occupies both sides so any
/// later side hits) — the check must not short-circuit: compute both
/// sides, then OR.
fn duplicate_magnet_identity(
    identity: &TorrentIdentity,
    seen_v1: &mut HashSet<[u8; 20]>,
    seen_v2: &mut HashSet<[u8; 32]>,
) -> bool {
    let v1_dup = identity.v1.is_some_and(|h| !seen_v1.insert(h));
    let v2_dup = identity.v2.is_some_and(|h| !seen_v2.insert(h));
    v1_dup || v2_dup
}

/// metaurl URI -> BT entry classification: `magnet:` passes through
/// (the existing magnet task path); an http(s) URI whose path tail ends
/// in `.torrent` (case-insensitive, query/fragment stripped) passes
/// through (the existing `.torrent` metadata-download entry); anything
/// else = None (skip + warn, declared difference). The same
/// classification anchor as core `is_torrent_url`.
fn torrent_entry_uri(uri: &str) -> Option<String> {
    if uri.starts_with("magnet:") {
        return Some(uri.to_string());
    }
    let path = uri.split(['?', '#']).next().unwrap_or(uri);
    let torrentish = path
        .rsplit('/')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase()
        .ends_with(".torrent");
    if torrentish && is_http_family_uri(uri) {
        Some(uri.to_string())
    } else {
        None
    }
}

/// Protocol-family filter for mirror/entry URIs (http/https/ftp/ftps —
/// the same rule as the core addUri classification `is_download_uri`;
/// the aria2 dropUnsupportedResource family). The scheme is
/// case-insensitive (RFC 3986 section 3.1 scheme normalization —
/// uppercase-scheme mirrors were once silently dropped).
fn is_http_family_uri(uri: &str) -> bool {
    let scheme = uri.split("://").next().unwrap_or("");
    matches!(
        scheme.to_ascii_lowercase().as_str(),
        "http" | "https" | "ftp" | "ftps"
    )
}

/// Entry name -> `--out` plain file-name domain (basename flatten;
/// module-doc declared difference). Names that cannot produce a legal
/// domain form (empty/`.`/`..`/leading `-`/backslash/colon/Windows
/// reserved stem/trailing `.` or space — the same cause table as the
/// core sanitize_out_option domain, single-sourced in
/// [`windows_unsafe_basename`]) = None (the entry is skipped + warning).
fn entry_out_name(name: &str) -> Option<String> {
    let base = name.rsplit('/').next().unwrap_or(name);
    let ok = !base.is_empty()
        && base != "."
        && base != ".."
        && !base.starts_with('-')
        && !base.contains('\\')
        && !base.contains(':')
        && !windows_unsafe_basename(base);
    ok.then(|| base.to_string())
}

/// Base-option pre-check for the metalink group: the legacy family is
/// ignored with a warning; a non-boolean auto-discover value =
/// `taiji.option.invalid` (value-domain rejection); true = accepted but
/// treated as invalid with a warning (declared difference). Returns the
/// net options with the metalink group keys stripped (the core addUri
/// option face never sees metalink keys — absorbed at this single seam).
pub(crate) fn sanitize_base_options(
    options: BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, RpcError> {
    let mut cleaned = BTreeMap::new();
    for (k, v) in options {
        if UNSUPPORTED_METALINK_OPTIONS.contains(&k.as_str()) {
            warn!(
                target: "taiji::rpc::metalink",
                option = %k,
                "metalink option family is not supported; ignored (declared difference)"
            );
            continue;
        }
        if k == AUTO_DISCOVER_OPTION {
            match v.trim().to_ascii_lowercase().as_str() {
                "true" => warn!(
                    target: "taiji::rpc::metalink",
                    "metalink auto-discovery is not implemented in this build; \
                     treated as false (declared difference)"
                ),
                "false" => {}
                _ => {
                    return Err(RpcError::option_invalid(format!(
                        "--metalink-enable-auto-discover {v:?} (want true|false)"
                    )));
                }
            }
            continue;
        }
        cleaned.insert(k, v);
    }
    Ok(cleaned)
}

/// `taiji.addMetalink` / `addMetalink` execution (feature on; the
/// dispatch layer has already done token stripping, auth, and the write
/// gate). Parameter surface (positional,
/// `AddMetalinkRpcMethod::process`):
///
/// `addMetalink(metalink, options?, position?)`
///
/// - `metalink`: base64 document (the JSON-RPC branch decodes base64
///   with the strict standard alphabet + padding — invalid = an
///   explicit execution error, the aria2 DECODE_FAILURE semantics);
/// - `options`: the per-task option dict (the base face, passed through
///   to every task; metalink group keys are absorbed here, see
///   [`sanitize_base_options`]);
/// - `position`: the queue insertion position (aria2
///   insertReservedGroup(pos) semantics — subtask i lands at
///   `position + i`, keeping in-group order).
///
/// The reply = a plain GID string array (document expansion order; the
/// aria2 gids face). If a subtask is rejected by the session
/// mid-expansion (duplicate identity / `out`-domain rejection etc.),
/// the whole method fails explicitly (numeric code 1 + the original
/// message; already-created tasks are kept — independent GIDs have
/// independent status, the structural face of failure isolation; the
/// error message carries the created GIDs so the caller can clean up,
/// the aria2 error object `{code,message}` shape unchanged). Benign
/// in-document duplicates (the same metaurl URI / the same magnet btih
/// identity) are absorbed at the expansion seam as skip + warning and
/// never reach this failure face.
///
/// # Parse budget and cancellation
///
/// base64 decoding and document parsing both run inside
/// spawn_blocking (within the 16MiB document cap the base64 payload
/// itself can reach ~7.5MiB; neither decode nor parse may occupy an
/// async thread), under the outer 600s timeout ceiling (the
/// `taiji.createTorrent` discipline — no synchronous RPC without a
/// timeout cap); timeout = `taiji.metalink.timeout`. A timeout or a
/// disconnected caller only bounds the reply; it does not interrupt the
/// underlying blocking parse (spawn_blocking is not cancellable). The
/// parse is a pure function (no task state, no disk side effects), so
/// discarding the result creates no orphan tasks and the caller can
/// retry safely.
pub(crate) async fn add_metalink_method(
    st: &crate::dispatch::AppState,
    params: &[Value],
    id: Value,
) -> RpcResponse {
    // Param 0: the base64 document (a required string; owned — handed to
    // the blocking thread with the decode closure).
    let raw: String = match params.first() {
        Some(Value::String(s)) => s.clone(),
        Some(_) => {
            return RpcResponse::error(&param_error(0, false), id);
        }
        None => {
            return RpcResponse::error(&param_error(0, true), id);
        }
    };
    // Decode + parse in one closure (the blocking face; v3/unknown
    // version = an explicit downgrade error — a declared difference; hard
    // errors = parse_failed).
    let parsed = tokio::time::timeout(
        METALINK_PARSE_TIMEOUT,
        spawn_blocking(move || base64::decode(&raw).map(|bytes| parse(&bytes))),
    )
    .await;
    let doc = match parsed {
        Ok(Ok(Some(Ok(doc)))) => doc,
        Ok(Ok(Some(Err(e)))) => return RpcResponse::error(&map_metalink_error(&e), id),
        Ok(Ok(None)) => {
            return RpcResponse::error(
                &RpcError::generic(crate::aria2::error::MSG_METALINK_NOT_BASE64),
                id,
            );
        }
        Ok(Err(e)) => {
            return RpcResponse::error(
                &RpcError::generic(format!("metalink parse join failed: {e}")),
                id,
            );
        }
        Err(_) => {
            return RpcResponse::error(
                &RpcError::generic(format!(
                    "{STR_METALINK_TIMEOUT}: metalink parse exceeded the \
                     {METALINK_PARSE_TIMEOUT:?} budget"
                )),
                id,
            );
        }
    };
    // options dict (explicit null/absent = empty; non-object = a type
    // error; non-string values skipped — the gatherOption rule).
    let raw_options = try_rpc!(id, opt_options(params, 1));
    let base = match sanitize_base_options(raw_options) {
        Ok(b) => b,
        Err(e) => return RpcResponse::error(&e, id),
    };
    // position (aria2 checkPosParam: null/absent/negative = not given).
    let position = try_rpc!(id, opt_position(params, 2));
    let plans = expand_add_uri_plans(&doc, base);
    let mut gids: Vec<Value> = Vec::with_capacity(plans.len());
    for (i, plan) in plans.iter().enumerate() {
        let position_i = position.map(|p| p + i);
        match st
            .session
            .call(SessionCommand::AddUri {
                uris: plan.uris.clone(),
                options: plan.options.clone(),
                position: position_i,
            })
            .await
        {
            Ok(CommandReply::Gid(g)) => gids.push(json!(g.to_string())),
            Ok(other) => {
                return fail_with_partial(
                    &gids,
                    RpcError::unexpected_reply("addMetalink", &other),
                    id,
                );
            }
            // Mid-expansion rejection = whole-method explicit failure
            // (created tasks kept; see the fn doc).
            Err(e) => return fail_with_partial(&gids, map_session_error(&e), id),
        }
    }
    // Zero usable tasks = an empty array (the aria2 result.empty() branch — not an error).
    RpcResponse::ok(Value::Array(gids), id)
}

/// Partial-failure reply: the error response carries the created GID
/// list (appended to the message — the aria2 error object shape is
/// unchanged; the caller can remove/tellStatus created tasks
/// independently).
fn fail_with_partial(gids: &[Value], mut err: RpcError, id: Value) -> RpcResponse {
    if !gids.is_empty() {
        let created: Vec<&str> = gids.iter().filter_map(|g| g.as_str()).collect();
        err.message
            .push_str(&format!(" (created gids: {})", created.join(",")));
    }
    RpcResponse::error(&err, id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> BTreeMap<String, String> {
        BTreeMap::from([("dir".to_string(), "/tmp/dl".to_string())])
    }

    fn parse_ok(doc: &str) -> Metalink {
        parse(doc.as_bytes()).unwrap_or_else(|e| panic!("fixture must parse: {e}"))
    }

    const TWO_FILES: &str = r#"<metalink xmlns="urn:ietf:params:xml:ns:metalink">
      <file name="a.iso"><size>3</size>
        <url priority="1">http://a.test/a.iso</url>
        <url priority="2">ftp://b.test/a.iso</url>
        <hash type="sha-256">aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa</hash>
        <hash type="md5">aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa</hash>
      </file>
      <file name="rel/sub/b.iso"><size>4</size>
        <url priority="1">https://c.test/b.iso</url>
      </file>
    </metalink>"#;

    /// Multi-file GID chain: one plan per entry in document order;
    /// subdirectory names flatten to basename; checksum takes an
    /// in-`--checksum`-domain declaration (six hashes, strongest wins:
    /// sha-256 over a weaker algorithm in the same entry).
    #[test]
    fn multi_file_expands_in_document_order_with_overrides() {
        let plans = expand_add_uri_plans(&parse_ok(TWO_FILES), base());
        assert_eq!(plans.len(), 2, "two file entries → two plans");
        assert_eq!(
            plans[0].uris,
            vec!["http://a.test/a.iso", "ftp://b.test/a.iso"]
        );
        assert_eq!(
            plans[0].options.get("out").map(String::as_str),
            Some("a.iso")
        );
        assert_eq!(
            plans[0].options.get("checksum").map(String::as_str),
            Some("sha-256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            "sha-256 wins over the weaker in-domain md5 declaration"
        );
        assert_eq!(
            plans[1].options.get("out").map(String::as_str),
            Some("b.iso"),
            "subdirectory names flatten to basename (declared difference)"
        );
        assert_eq!(plans[1].uris, vec!["https://c.test/b.iso"]);
        assert!(
            !plans[1].options.contains_key("checksum"),
            "entry without in-domain hash carries no checksum"
        );
        // Base options pass through to every plan (the dir face).
        assert_eq!(
            plans[0].options.get("dir").map(String::as_str),
            Some("/tmp/dl")
        );
    }

    /// Six-hash domain: an entry declaring only sha-512 (or md5/
    /// sha-224/sha-384) still gets a verdict — `<hash>` folds into the
    /// `checksum` option; when sha-256 coexists with weaker algorithms,
    /// sha-256 wins (strongest in domain, not the first weak one);
    /// out-of-domain kinds still produce nothing.
    #[test]
    fn six_algorithm_hash_declarations_fold_into_checksum_verdict() {
        // Single-algorithm entries, one per algorithm (hex length =
        // digest bytes x 2 — a legal form for the parser's length
        // check).
        for (kind, hexlen) in [
            ("md5", 32usize),
            ("sha-1", 40),
            ("sha-224", 56),
            ("sha-256", 64),
            ("sha-384", 96),
            ("sha-512", 128),
        ] {
            let doc = parse_ok(&format!(
                r#"<metalink xmlns="urn:ietf:params:xml:ns:metalink">
                  <file name="a.iso"><size>3</size>
                    <url priority="1">http://a.test/a.iso</url>
                    <hash type="{kind}">{}</hash>
                  </file>
                </metalink>"#,
                "b".repeat(hexlen)
            ));
            let plans = expand_add_uri_plans(&doc, base());
            assert_eq!(plans.len(), 1, "{kind}: one HTTP plan");
            assert_eq!(
                plans[0].options.get("checksum").map(String::as_str),
                Some(format!("{kind}={}", "b".repeat(hexlen)).as_str()),
                "{kind}-only declaration must fold into the checksum verdict"
            );
        }
        // Strongest wins: md5 declared first + sha-256 after -> sha-256 wins.
        let doc = parse_ok(
            r#"<metalink xmlns="urn:ietf:params:xml:ns:metalink">
              <file name="a.iso"><size>3</size>
                <url priority="1">http://a.test/a.iso</url>
                <hash type="md5">cccccccccccccccccccccccccccccccc</hash>
                <hash type="sha-256">dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd</hash>
              </file>
            </metalink>"#,
        );
        let plans = expand_add_uri_plans(&doc, base());
        assert_eq!(
            plans[0].options.get("checksum").map(String::as_str),
            Some("sha-256=dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"),
            "sha-256 is preferred over weaker in-domain kinds"
        );
        // Out-of-domain kind (sha3-512) still produces nothing (not folded in).
        let doc = parse_ok(
            r#"<metalink xmlns="urn:ietf:params:xml:ns:metalink">
              <file name="a.iso"><size>3</size>
                <url priority="1">http://a.test/a.iso</url>
                <hash type="sha3-512">eeee</hash>
              </file>
            </metalink>"#,
        );
        let plans = expand_add_uri_plans(&doc, base());
        assert_eq!(plans.len(), 1, "entry still expands (hash is advisory)");
        assert!(
            !plans[0].options.contains_key("checksum"),
            "out-of-domain hash kind must not produce a checksum"
        );
    }

    const METAURL_DOC: &str = r#"<metalink xmlns="urn:ietf:params:xml:ns:metalink">
      <file name="x.iso"><size>3</size>
        <url>http://a.test/x.iso</url>
        <metaurl mediatype="torrent" priority="1">magnet:?xt=urn:btih:1111111111111111111111111111111111111111&amp;dn=x</metaurl>
      </file>
      <file name="y.iso"><size>3</size>
        <metaurl mediatype="torrent">https://t.test/y.torrent?x=1</metaurl>
      </file>
      <file name="z.iso"><size>3</size>
        <metaurl mediatype="torrent">https://t.test/y.torrent?x=1</metaurl>
      </file>
    </metalink>"#;

    /// metaurl direct BT conversion: magnet -> magnet entry; a
    /// `.torrent`-suffixed http(s) -> metadata entry; same-URI dedup
    /// (y/z share, the BT task is produced once at the first entry);
    /// an entry's BT GID precedes that entry's HTTP GIDs (aria2's
    /// torrentRg-before-rg shape).
    #[test]
    fn metaurls_route_into_existing_torrent_entries_with_dedup() {
        let plans = expand_add_uri_plans(&parse_ok(METAURL_DOC), base());
        assert_eq!(
            plans.len(),
            3,
            "BT(x) + http(x) + BT(y); z shares the metaurl and has no urls of its own"
        );
        assert!(
            plans[0].uris[0].starts_with("magnet:"),
            "magnet metaurl → magnet entry: {:?}",
            plans[0].uris
        );
        assert_eq!(plans[0].uris.len(), 1, "BT entry = single URI");
        assert_eq!(plans[1].uris, vec!["http://a.test/x.iso"], "http face of x");
        assert_eq!(
            plans[2].uris,
            vec!["https://t.test/y.torrent?x=1"],
            ".torrent URL → metadata entry (query stripped only for the suffix check)"
        );
    }

    /// Expansion guards: non-torrent mediatype and non-`.torrent`
    /// non-magnet metaurls skipped; entries with no usable mirrors
    /// skipped; entry names outside the `--out` domain skipped; all
    /// unusable = an empty plan sequence (the empty-array half of the
    /// reply).
    #[test]
    fn unusable_entries_are_skipped_and_empty_doc_yields_no_plans() {
        let doc = parse_ok(
            r#"<metalink xmlns="urn:ietf:params:xml:ns:metalink">
              <file name="a.iso"><url>http://a.test/a.iso</url>
                <metaurl mediatype="zsync">http://z.test/a.zsync</metaurl></file>
              <file name="b.iso"><metaurl mediatype="torrent">http://b.test/get/12</metaurl></file>
              <file name="-c.iso"><url>http://c.test/c.iso</url></file>
              <file name="d.iso"><url>rsync://d.test/d.iso</url></file>
            </metalink>"#,
        );
        let plans = expand_add_uri_plans(&doc, base());
        assert_eq!(plans.len(), 1, "only a.iso survives");
        assert_eq!(plans[0].uris, vec!["http://a.test/a.iso"]);
        // A zero-entry document is rejected at parse (ParseFailed);
        // all-unusable entries = empty plans.
        let doc = parse_ok(
            r#"<metalink xmlns="urn:ietf:params:xml:ns:metalink">
              <file name="d.iso"><url>rsync://d.test/d.iso</url></file>
            </metalink>"#,
        );
        assert!(expand_add_uri_plans(&doc, base()).is_empty());
    }

    /// Duplicate magnet identity (same btih, different dn spelling)
    /// across entries: the later BT candidate is skipped (first wins)
    /// while later entries' HTTP faces are produced normally — a benign
    /// duplicate no longer fails the whole method halfway through the
    /// document.
    #[test]
    fn duplicate_magnet_identity_skips_bt_but_keeps_later_entries() {
        let doc = parse_ok(
            r#"<metalink xmlns="urn:ietf:params:xml:ns:metalink">
              <file name="x.iso"><size>3</size>
                <url priority="1">http://a.test/x.iso</url>
                <metaurl mediatype="torrent">magnet:?xt=urn:btih:1111111111111111111111111111111111111111&amp;dn=x</metaurl>
              </file>
              <file name="y.iso"><size>3</size>
                <url priority="1">http://b.test/y.iso</url>
                <metaurl mediatype="torrent">magnet:?xt=urn:btih:1111111111111111111111111111111111111111&amp;dn=y-copy&amp;tr=http%3A%2F%2Ft%2Fa</metaurl>
              </file>
              <file name="z.iso"><size>3</size>
                <metaurl mediatype="torrent">magnet:?xt=urn:btih:2222222222222222222222222222222222222222&amp;dn=z</metaurl>
              </file>
            </metalink>"#,
        );
        let plans = expand_add_uri_plans(&doc, base());
        assert_eq!(
            plans.len(),
            4,
            "BT(x) + http(x) + http(y) + BT(z); y's duplicate magnet BT is skipped at the seam \
             while its HTTP face and z's BT still emit: {plans:?}"
        );
        assert!(
            plans[0].uris[0].starts_with("magnet:"),
            "BT(x) at first slot"
        );
        assert_eq!(plans[1].uris, vec!["http://a.test/x.iso"]);
        assert_eq!(
            plans[2].uris,
            vec!["http://b.test/y.iso"],
            "y survives as its HTTP face only"
        );
        assert_eq!(
            plans[3].uris[0], "magnet:?xt=urn:btih:2222222222222222222222222222222222222222&dn=z",
            "z's distinct magnet is unaffected"
        );
    }

    /// btmh (v2 identity) dimension, same criterion: the same btmh with
    /// a different spelling = duplicate; a hybrid dual-xt magnet
    /// occupies both sides — a hit on either side deduplicates.
    #[test]
    fn duplicate_btmh_identity_is_also_deduplicated() {
        let btmh = "magnet:?xt=urn:btmh:1220aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let doc = parse_ok(&format!(
            r#"<metalink xmlns="urn:ietf:params:xml:ns:metalink">
              <file name="a.iso"><size>1</size>
                <metaurl mediatype="torrent">{btmh}&amp;dn=a</metaurl>
              </file>
              <file name="b.iso"><size>1</size>
                <metaurl mediatype="torrent">{btmh}&amp;dn=b</metaurl>
              </file>
              <file name="c.iso"><size>1</size>
                <metaurl mediatype="torrent">magnet:?xt=urn:btmh:1220bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb&amp;dn=c</metaurl>
              </file>
            </metalink>"#
        ));
        let plans = expand_add_uri_plans(&doc, base());
        assert_eq!(
            plans.len(),
            2,
            "same btmh deduped; different btmh survives: {plans:?}"
        );
        // Hybrid dual xt (btih 33 + btmh aa): a v1 hit against the
        // earlier btih 33 deduplicates (both ids must be registered; the
        // check must not short-circuit).
        let doc = parse_ok(
            r#"<metalink xmlns="urn:ietf:params:xml:ns:metalink">
              <file name="h1.iso"><size>1</size>
                <metaurl mediatype="torrent">magnet:?xt=urn:btih:3333333333333333333333333333333333333333&amp;xt=urn:btmh:1220cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc</metaurl>
              </file>
              <file name="h2.iso"><size>1</size>
                <metaurl mediatype="torrent">magnet:?xt=urn:btih:3333333333333333333333333333333333333333</metaurl>
              </file>
            </metalink>"#,
        );
        let plans = expand_add_uri_plans(&doc, base());
        assert_eq!(
            plans.len(),
            1,
            "hybrid identity dedup via its v1 face: {plans:?}"
        );
    }

    /// An unusable first torrent-mediatype candidate no longer blocks a
    /// later usable one: candidates are examined within the entry until
    /// the first BT task is produced.
    #[test]
    fn unusable_first_torrent_metaurl_yields_to_later_usable_one() {
        let doc = parse_ok(
            r#"<metalink xmlns="urn:ietf:params:xml:ns:metalink">
              <file name="a.iso"><size>3</size>
                <metaurl mediatype="torrent" priority="1">http://b.test/get/12</metaurl>
                <metaurl mediatype="torrent" priority="2">magnet:?xt=urn:btih:4444444444444444444444444444444444444444&amp;dn=a</metaurl>
              </file>
            </metalink>"#,
        );
        let plans = expand_add_uri_plans(&doc, base());
        assert_eq!(
            plans.len(),
            1,
            "first unusable candidate skipped, later magnet consumed: {plans:?}"
        );
        assert!(
            plans[0].uris[0].starts_with("magnet:"),
            "BT entry comes from the later usable candidate: {:?}",
            plans[0].uris
        );
    }

    /// The legacy metalink family + the auto-discover option absorbed
    /// at one point (the seam's net option face).
    #[test]
    fn metalink_option_family_is_absorbed_at_the_seam() {
        let mut opts = base();
        opts.insert("metalink-location".into(), "JP,US".into());
        opts.insert("metalink-preferred-protocol".into(), "https".into());
        opts.insert("metalink-enable-auto-discover".into(), "true".into());
        opts.insert("user-agent".into(), "ua/1".into());
        let cleaned = sanitize_base_options(opts).unwrap_or_else(|e| panic!("clean: {e:?}"));
        assert!(!cleaned.contains_key("metalink-location"));
        assert!(!cleaned.contains_key("metalink-preferred-protocol"));
        assert!(!cleaned.contains_key("metalink-enable-auto-discover"));
        assert_eq!(cleaned.get("user-agent").map(String::as_str), Some("ua/1"));
        assert_eq!(cleaned.get("dir").map(String::as_str), Some("/tmp/dl"));
        // A non-boolean auto-discover value = taiji.option.invalid (value-domain rejection).
        let mut bad = base();
        bad.insert("metalink-enable-auto-discover".into(), "yes".into());
        let err = match sanitize_base_options(bad) {
            Err(e) => e,
            Ok(_) => panic!("non-bool auto-discover must be refused"),
        };
        assert!(
            err.message.starts_with("taiji.option.invalid"),
            "invalid auto-discover value: {err:?}"
        );
    }

    /// basename flatten domain boundaries (the `--out` domain cause
    /// table; the Windows additions mirror the core
    /// `windows_unsafe_basename` single source).
    #[test]
    fn out_name_domain_boundaries() {
        assert_eq!(entry_out_name("a/b/c.iso").as_deref(), Some("c.iso"));
        assert_eq!(entry_out_name("plain.iso").as_deref(), Some("plain.iso"));
        assert_eq!(entry_out_name("-lead.iso"), None, "leading dash refused");
        assert_eq!(entry_out_name("back\\.iso"), None, "backslash refused");
        assert_eq!(entry_out_name("C:colon.iso"), None, "drive colon refused");
        assert_eq!(entry_out_name("dir/"), None, "trailing slash → empty base");
        assert_eq!(entry_out_name("dir/.."), None, "dot-dot base refused");
        // Windows naming domain: reserved device-name stems
        // (case-insensitive, including with extensions) and trailing
        // `.`/space (Win32 strips them on disk -> unexpected renames/
        // collisions).
        assert_eq!(entry_out_name("CON"), None, "reserved stem refused");
        assert_eq!(entry_out_name("sub/aux.iso"), None, "reserved aux refused");
        assert_eq!(entry_out_name("Lpt3.zip"), None, "case-insensitive stem");
        assert_eq!(entry_out_name("trail."), None, "trailing dot refused");
        assert_eq!(entry_out_name("trail "), None, "trailing space refused");
        assert_eq!(
            entry_out_name("const.iso").as_deref(),
            Some("const.iso"),
            "stem that merely contains a reserved word stays accepted"
        );
    }

    // ---- Expansion negative tests ----

    /// (dir,out) collision after basename flattening: sub1/a.iso and
    /// sub2/a.iso (and a duplicate `<file name>`) collapse onto one part
    /// file — later entries skipped with a warning; the first entry owns
    /// (dir,out) exclusively.
    #[test]
    fn duplicate_dir_out_after_flattening_skips_later_entries() {
        let doc = parse_ok(
            r#"<metalink xmlns="urn:ietf:params:xml:ns:metalink">
              <file name="sub1/a.iso"><size>3</size><url priority="1">http://a.test/a.iso</url></file>
              <file name="sub2/a.iso"><size>3</size><url priority="1">http://b.test/a.iso</url></file>
              <file name="a.iso"><size>3</size><url priority="1">http://c.test/a.iso</url></file>
            </metalink>"#,
        );
        let plans = expand_add_uri_plans(&doc, base());
        assert_eq!(
            plans.len(),
            1,
            "three entries flatten to one (dir,out); only the first may occupy it: {plans:?}"
        );
        assert_eq!(plans[0].uris, vec!["http://a.test/a.iso"]);
        // Same-name entries under different dirs do not collide (the
        // occupancy key is the (dir,out) pair).
        let mut other_dir = base();
        other_dir.insert("dir".into(), "/tmp/other".into());
        let plans = expand_add_uri_plans(&doc, other_dir);
        assert_eq!(plans.len(), 1, "(dir,out) key is dir-scoped");
    }

    /// checksum leak guard: the caller's --checksum must not enter
    /// entries without a document checksum declaration (fail-closed leak
    /// surface); when an entry has its own declaration the document
    /// value always wins; BT plans never carry the caller's checksum
    /// either.
    #[test]
    fn caller_checksum_does_not_leak_into_undocumented_entries() {
        let mut base_opts = base();
        base_opts.insert(
            "checksum".to_string(),
            "sha-256=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
        );
        let doc = parse_ok(TWO_FILES);
        let plans = expand_add_uri_plans(&doc, base_opts.clone());
        assert_eq!(
            plans[0].options.get("checksum").map(String::as_str),
            Some("sha-256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            "document hash wins over the caller's checksum"
        );
        assert!(
            !plans[1].options.contains_key("checksum"),
            "entry without a document hash must not inherit the caller's --checksum"
        );
        // BT (metaurl) plans do not inherit the caller's checksum.
        let plans = expand_add_uri_plans(&parse_ok(METAURL_DOC), base_opts.clone());
        assert!(
            plans.iter().all(|p| !p.options.contains_key("checksum")),
            "no plan may carry the caller's checksum"
        );
        // Likewise: the caller's out enters no plan (BT plans have no
        // out face; HTTP plans are overridden by the entry name, with no
        // caller residue).
        let mut base_out = base();
        base_out.insert("out".into(), "caller.bin".into());
        let plans = expand_add_uri_plans(&parse_ok(METAURL_DOC), base_out);
        assert_eq!(plans.len(), 3, "BT(x) + http(x) + BT(y)");
        assert!(
            !plans[0].options.contains_key("out") && !plans[2].options.contains_key("out"),
            "BT plans must not inherit the caller out"
        );
        assert_eq!(
            plans[1].options.get("out").map(String::as_str),
            Some("x.iso"),
            "http plan carries the entry-derived out only"
        );
    }

    /// url@priority consumed at expansion: mirrors stably pre-sorted by
    /// priority ascending (1 = best; equal priorities keep document
    /// order); out-of-domain mirror filtering is unaffected by sorting.
    #[test]
    fn mirror_priority_orders_the_multi_source_plan() {
        let doc = parse_ok(
            r#"<metalink xmlns="urn:ietf:params:xml:ns:metalink">
              <file name="a.iso"><size>3</size>
                <url priority="5">http://slow.test/a.iso</url>
                <url priority="1">http://fast1.test/a.iso</url>
                <url priority="2">ftp://mid.test/a.iso</url>
                <url priority="1">http://fast2.test/a.iso</url>
                <url priority="1">rsync://dropped.test/a.iso</url>
              </file>
            </metalink>"#,
        );
        let plans = expand_add_uri_plans(&doc, base());
        assert_eq!(
            plans[0].uris,
            vec![
                "http://fast1.test/a.iso",
                "http://fast2.test/a.iso",
                "ftp://mid.test/a.iso",
                "http://slow.test/a.iso",
            ],
            "priority ascending, document order within equal priority"
        );
    }

    /// Scheme case normalization: uppercase-scheme mirrors/`.torrent`
    /// entries were once silently dropped by literal prefix (RFC 3986
    /// section 3.1 scheme normalization).
    #[test]
    fn uppercase_scheme_mirrors_are_accepted() {
        let doc = parse_ok(
            r#"<metalink xmlns="urn:ietf:params:xml:ns:metalink">
              <file name="a.iso"><size>3</size>
                <url>HTTP://a.test/a.iso</url>
                <url>Https://b.test/a.iso</url>
                <url>rsync://skip.test/a.iso</url>
              </file>
              <file name="t.iso"><size>3</size>
                <metaurl mediatype="TORRENT">HTTPS://t.test/t.TORRENT?x=1</metaurl>
              </file>
            </metalink>"#,
        );
        let plans = expand_add_uri_plans(&doc, base());
        assert_eq!(
            plans.len(),
            2,
            "uppercase-scheme mirrors form one multi-source plan + one BT entry"
        );
        assert_eq!(
            plans[0].uris,
            vec!["HTTP://a.test/a.iso", "Https://b.test/a.iso"],
            "uppercase-scheme mirrors are not silently dropped"
        );
        assert_eq!(plans[1].uris, vec!["HTTPS://t.test/t.TORRENT?x=1"]);
    }

    /// Partial-failure reply: created GIDs appended to the error message
    /// (the `{code,message}` error object shape unchanged); zero created
    /// = the original message.
    #[test]
    fn partial_failure_receipt_carries_created_gids() {
        use crate::aria2::error::map_metalink_error;
        let gids = [json!("8000000000000001"), json!("8000000000000002")];
        let r = fail_with_partial(
            &gids,
            map_metalink_error(&taiji_metalink::MetalinkError::ParseFailed {
                reason: "x".to_string(),
            }),
            json!("t"),
        );
        assert_eq!(r.code, 1);
        assert!(
            r.payload["message"]
                .as_str()
                .is_some_and(|m| m.ends_with(" (created gids: 8000000000000001,8000000000000002)")),
            "created gids appended: {}",
            r.payload["message"]
        );
        // Zero created = the original message (no tail appended).
        let r = fail_with_partial(
            &[],
            crate::aria2::error::RpcError::generic("boom"),
            json!("t"),
        );
        assert_eq!(r.payload["message"], json!("boom"));
    }

    // ---- metalink option governance: the seam's accepted names must all be declared ----

    /// Every name the seam accepts (the legacy ignore family + the
    /// auto-discover option + CLI `--metalink-file`) must be registered
    /// in the core declaration table (a reference name or a difference
    /// whitelist entry) — a seam name without a declaration fails.
    /// Reference names land in
    /// [`taiji_core::session::options::ARIA2_OPTION_NAMES`],
    /// non-reference names in DECLARED_OPTION_DIFFS.
    #[test]
    fn metalink_seam_accepts_only_declared_option_names() {
        use taiji_core::session::{
            ARIA2_OPTION_NAMES, DECLARED_OPTION_DIFFS, option_name_declared,
        };
        let mut seam: Vec<&str> = UNSUPPORTED_METALINK_OPTIONS.to_vec();
        seam.push(AUTO_DISCOVER_OPTION);
        seam.push("metalink-file"); // the CLI `--metalink-file` face.
        for name in &seam {
            assert!(
                option_name_declared(name),
                "metalink seam accepted name {name:?} is not registered in the declaration table (core session::options)"
            );
        }
        // Non-reference names (accepted, absent from aria2 1.37.0
        // prefs.cc) must go through the difference whitelist, not the
        // reference list — accepted but declared as differences.
        for name in [AUTO_DISCOVER_OPTION, "metalink-force-protocol"] {
            assert!(
                DECLARED_OPTION_DIFFS.iter().any(|(n, _)| *n == name),
                "{name} must be declared as a difference entry (aria2 has no such name)"
            );
            assert!(
                !ARIA2_OPTION_NAMES.contains(&name),
                "{name} is not an aria2 reference name and must not sneak into the reference list"
            );
        }
        // Mirror check: the core test face
        // METALINK_ACCEPTED_SEAM_OPTION_NAMES must match this seam's
        // accepted set in size and names — a seam change without a
        // mirror update fails.
        let mut seam_set: Vec<&str> = seam.clone();
        seam_set.sort_unstable();
        let mirror: Vec<&str> = vec![
            "metalink-enable-auto-discover",
            "metalink-enable-unique-protocol",
            "metalink-file",
            "metalink-force-protocol",
            "metalink-language",
            "metalink-location",
            "metalink-os",
            "metalink-preferred-protocol",
            "metalink-version",
        ];
        assert_eq!(
            seam_set, mirror,
            "the metalink seam's accepted set drifted (the core mirror = 9 names)"
        );
    }
}

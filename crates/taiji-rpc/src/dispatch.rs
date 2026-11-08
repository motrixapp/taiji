//! Method dispatch, session method semantics, and RPC-layer
//! system.multicall expansion.
//!
//! Dispatch-order invariants (cross-validated against the aria2
//! reference): authorize runs before process — unknown methods are
//! authenticated first too (`RpcMethod.cc`); system.listMethods /
//! system.listNotifications override execute and skip authorize
//! (`RpcMethodImpl.cc`); system.multicall sinks auth into the
//! sub-calls (any unauthorized sub-call delays the whole response) and
//! recursion is forbidden; success wraps in a list, errors inline.
//! multicall expands at the RPC layer into multiple
//! `SessionHandle::call`s and does not enter core (the SessionCommand
//! surface is untouched).
//!
//! Module layout (the `crate::dispatch::*` facade paths are unchanged):
//! this file keeps the dispatch order, `AppState`, method-name alias
//! normalization and the `--rpc-aria2-compat` API-face gate
//! ([`canonical_method`], one API face at a time) and the multicall/
//! batch item caps; aria2 JSON rendering in [`view`]; parameter
//! decoding helpers in [`params`]; session method execution in
//! [`methods`]; system.multicall / system.list* in [`multicall`];
//! single/batch payload handling in [`payload`].
//!
//! Upstream anchor mapping: docs/design/rpc.md

use serde_json::Value;
use std::net::IpAddr;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use tracing::warn;

use taiji_core::session::{RPC_METHOD_INFO, RPC_METHOD_SLOT_UNKNOWN, RPC_METHODS, SessionHandle};

use crate::auth;
use crate::error::{RpcError, STR_UNAUTH_WRITE};
use crate::guards::{AuthBackoff, ConnLedger};
use crate::jsonrpc::RpcResponse;

mod methods;
mod multicall;
// pub(crate): the metalink consumption seam (crate::metalink) reuses
// the parameter-decoding helpers (opt_options/opt_position/param_error/
// try_rpc — the addMetalink parameter face shares the addUri template
// wording).
pub(crate) mod params;
mod payload;
mod view;

use methods::execute_session_method;
use multicall::{list_of, process_multicall};
pub(crate) use payload::{MAX_BATCH_ITEMS, RpcOutcome, handle_payload, too_many_items};

#[cfg(test)]
use payload::single;
#[cfg(test)]
use serde_json::json;
#[cfg(test)]
use taiji_core::session::TorrentStatusView;
pub use view::ENABLED_FEATURES;
/// The production render chain's sub-kind conversion (shared in-crate —
/// the mapping-table end-to-end test consumes it at the same point;
/// private test copies are forbidden).
#[cfg(test)]
pub(crate) use view::engine_kind;
#[cfg(test)]
use view::{pagination_range, render_status_list};

/// The six event notification names (the canonical face:
/// `taiji.onXxx`, the payload `[{gid}]` unchanged). Same source as the
/// core `EventKind::notification_method` (locked by a consistency
/// test); `system.listNotifications` emits this table directly in the
/// default (compat off) state.
pub const RPC_NOTIFICATIONS: &[&str] = &[
    "taiji.onDownloadStart",
    "taiji.onDownloadPause",
    "taiji.onDownloadStop",
    "taiji.onDownloadComplete",
    "taiji.onDownloadError",
    "taiji.onBtDownloadComplete",
];

/// The six event notification names (the `--rpc-aria2-compat` alias
/// face). Verbatim cross-validation: `RpcMethodFactory.cc` (the
/// system.listNotifications table) and `WebSocketSessionMan.cc` (the
/// WS push method names) — one-to-one with the canonical table
/// (`taiji.X` <-> `aria2.X`); the extension events (`taiji.recovery*`)
/// are not in this table (the compat face covers only the six events).
pub const RPC_NOTIFICATIONS_ARIA2: &[&str] = &[
    "aria2.onDownloadStart",
    "aria2.onDownloadPause",
    "aria2.onDownloadStop",
    "aria2.onDownloadComplete",
    "aria2.onDownloadError",
    "aria2.onBtDownloadComplete",
];

/// The listNotifications presentation-face selector (one API face at a time).
pub(crate) fn notification_face(aria2_compat: bool) -> &'static [&'static str] {
    if aria2_compat {
        RPC_NOTIFICATIONS_ARIA2
    } else {
        RPC_NOTIFICATIONS
    }
}

/// The dispatch context (assembled in server.rs; unit tests construct it directly).
pub(crate) struct AppState {
    pub session: Arc<SessionHandle>,
    pub secret: Option<String>,
    /// The HTTP Basic auth face (None = `--rpc-user` unset -> the Basic
    /// layer is off, `HttpServer.cc`). Plaintext is folded into a
    /// process-random HMAC tag inside serve().
    pub basic: Option<auth::BasicAuth>,
    pub allow_origin_all: bool,
    pub max_request_size: usize,
    /// Graceful shutdown root: cancelled once shutdown/forceShutdown is
    /// accepted (the CLI exits via this token).
    pub shutdown: CancellationToken,
    /// `--rpc-aria2-compat` (the alias mode; default false, a
    /// session-level startup option). true = methods accept `aria2.*`
    /// aliases, the six events push as `aria2.onXxx`, and
    /// listMethods/listNotifications present the aria2 face; false =
    /// the single canonical `taiji.*` face. Only one API face exists at
    /// a time (dual emission is forbidden); the `system.*` introspection
    /// family and the `taiji.*` extension methods/events keep the same
    /// names in both states (unaffected by the face switch).
    pub aria2_compat: bool,
    /// `--rpc-listen-all` (the sole decider of the bind axis; the
    /// server's combination guard consumes the same cfg value).
    /// AppState-side consumer: with listen_all + a secret (Basic unset
    /// or user-only — a password-less zero-entropy form), the two
    /// anonymous faces /metrics and the WS event stream are gated by the
    /// secret itself — a network-open bind face must not expose them
    /// without credentials.
    pub listen_all: bool,
    /// The connection concurrency ledger (total + per IP; caps injected
    /// at construction, not a CLI face). Consumed by the server's
    /// connection gate (`conn_gate`) and the WS session leases.
    pub conn: Arc<ConnLedger>,
    /// Exponential auth-failure backoff (a per-IP ledger merging
    /// failures from the token and Basic gates; the threshold is
    /// injected at construction, not a CLI face).
    pub auth_backoff: Arc<AuthBackoff>,
}

impl AppState {
    pub(crate) fn secret(&self) -> Option<&str> {
        self.secret.as_deref()
    }
}

/// Method name -> frozen-face canonical name (the single alias
/// normalization source; the `--rpc-aria2-compat` alias mode is gated
/// at this single point — one API face at a time). Resolution order:
/// 1. exact full-name hit in [`RPC_METHODS`] (bare names + the
///    `system.*`/`taiji.*` extension literals);
/// 2. prefix alias normalization: `taiji.<bare>` is always accepted
///    (the canonical `taiji.addUri` converges to the frozen bare name
///    here); `aria2.<bare>` only when `aria2_compat` is on. Aliases
///    apply to bare names only (dotted names never re-match — the
///    `taiji.moveStorage`-style extension literals and `system.*` have
///    no prefix alias form).
///
/// The canonical namespace is `taiji.*`; `aria2.*` exists only in
/// compat mode: with it off, `aria2.*` calls land on the unknown-method
/// face ("No such method: aria2.X" after authorize — the reference
/// wording).
fn canonical_method(name: &str, aria2_compat: bool) -> Option<&'static str> {
    if let Some(m) = RPC_METHODS.iter().find(|m| **m == name) {
        return Some(m);
    }
    let bare = name.strip_prefix("taiji.").or_else(|| {
        if aria2_compat {
            name.strip_prefix("aria2.")
        } else {
            None
        }
    })?;
    // Alias normalization converges only to frozen bare names (dotted =
    // extension literals / the introspection family, no aliases).
    if bare.contains('.') {
        return None;
    }
    RPC_METHODS.iter().copied().find(|m| *m == bare)
}

/// The listMethods presentation face (one API face at a time). A
/// projection of the registration face [`RPC_METHODS`], the single
/// source of truth:
/// - entries with a `.` literal (`system.*` introspection, `taiji.*`
///   extensions) pass through unchanged on both faces;
/// - bare names (the aria2-compatible family) get the face prefix —
///   canonical `taiji.<bare>`, compat `aria2.<bare>` (the reference's
///   rpcMethodNames are all presented prefixed, `RpcMethodFactory.cc`;
///   table order follows the registration face).
pub(crate) fn method_face_names(aria2_compat: bool) -> Vec<String> {
    let prefix = if aria2_compat { "aria2." } else { "taiji." };
    RPC_METHODS
        .iter()
        .map(|m| {
            if m.contains('.') {
                (*m).to_string()
            } else {
                format!("{prefix}{m}")
            }
        })
        .collect()
}

/// The single-call entry (the counting face): every call (including
/// batch/multicall sub-calls, identical for the POST and WS transports)
/// counts `taiji_rpc_requests_total{method}` + the latency histogram
/// (the full dispatch entry: auth, parameter decoding, session round
/// trip; HTTP-layer unauthorized delays excluded — they are delayed
/// after this function returns). The method label is anchored to the
/// frozen method table; unknown names merge into the single `unknown`
/// slot (anti-cardinality-injection). `ip` = the transport-layer peer
/// address (the per-IP auth-failure backoff key; None = the in-process
/// test face, no accounting). The real dispatch is in
/// [`process_call_inner`].
pub(crate) async fn process_call(
    st: &AppState,
    raw_method: &str,
    params: Vec<Value>,
    id: Value,
    in_multicall: bool,
    ip: Option<IpAddr>,
) -> RpcResponse {
    let slot = canonical_method(raw_method, st.aria2_compat)
        .and_then(|m| RPC_METHODS.iter().position(|x| *x == m))
        .unwrap_or(RPC_METHOD_SLOT_UNKNOWN);
    let metrics = st.session.metrics();
    metrics.note_rpc_request(slot);
    let started = std::time::Instant::now();
    let resp = process_call_inner(st, raw_method, params, id, in_multicall, ip).await;
    metrics.observe_rpc_duration(started.elapsed());
    resp
}

/// The read-only method face (the write-gate exemption set): query /
/// enumeration methods — no task add/remove, no option changes, no
/// shutdown side effects. The single source of truth = the core
/// registry [`RPC_METHOD_INFO`] (registered alongside [`RPC_METHODS`];
/// governance tests lock exact two-way equality; per-method read/write
/// rationale lives in the registry entries) — a hand-written list
/// drifting from the frozen method face is a security-hole shape: a
/// write method slipping into the exemption set = the write gate
/// failing when `--rpc-secret` is unset. Off-table names fail closed
/// as write faces (canonical_method only yields table names; a
/// defensive bottom line).
///
/// Why the write gate fails closed: every other session method
/// (addUri/addTorrent/remove/change*/pause*/shutdown/...) is rejected
/// when `--rpc-secret` is unset — an unauthenticated loopback RPC can
/// be driven cross-origin by a browser (a text/plain simple request +
/// WS cross-origin), and per-task hook options with an arbitrary dir
/// escalate to code execution / arbitrary path writes. system.list* is
/// not authenticated at the dispatch layer (the reference overrides
/// execute); multicall's write gate sinks to the sub-calls one by one.
fn is_read_only(method: &str) -> bool {
    let Some(entry) = RPC_METHOD_INFO.iter().find(|entry| entry.name == method) else {
        return false;
    };
    entry.read_only
}

/// The write-operation gate (security fix): with `--rpc-secret` unset
/// the token layer is always true (validate(None, _) like the
/// reference `DownloadEngine.cc`), and binding 127.0.0.1 alone does
/// not stop a same-machine browser — so every mutating face fails
/// closed here. The wording is frozen as [`STR_UNAUTH_WRITE`] (an
/// externally visible fix face).
fn unauthenticated_write_error(id: Value) -> RpcResponse {
    RpcResponse::error(&RpcError::generic(STR_UNAUTH_WRITE), id)
}

/// The token gate + auth-failure backoff: strip the `token:` first
/// parameter -> inside a window, wait first (even with correct
/// credentials — the window punishes the source, not the credential)
/// -> validate -> on failure count it (the same per-IP ledger as the
/// Basic gate) / on success reset. With no secret configured it is
/// always true (`DownloadEngine.cc`) and never touches the ledger —
/// the token layer has no credential to check and this is not an auth
/// attempt (the no-credential localhost form never touches it).
async fn token_gate(st: &AppState, ip: Option<IpAddr>, params: &mut Vec<Value>) -> bool {
    let token = auth::strip_token(params);
    if st.secret.is_none() {
        return auth::validate(st.secret(), token.as_deref());
    }
    st.auth_backoff.wait(ip).await;
    let ok = auth::validate(st.secret(), token.as_deref());
    if ok {
        st.auth_backoff.note_success(ip);
    } else {
        st.session.metrics().note_rpc_auth_fail();
        if let Some(window) = st.auth_backoff.note_failure(ip) {
            // Credential contents never enter logs — only the peer and the window length.
            warn!(
                target: "taiji::rpc::dispatch",
                ?ip,
                window_secs = window.as_secs(),
                "auth failure backoff window armed"
            );
        }
    }
    ok
}

/// The single-call entry shared by top-level calls and multicall
/// sub-calls (`in_multicall` enables the recursion guard).
async fn process_call_inner(
    st: &AppState,
    raw_method: &str,
    mut params: Vec<Value>,
    id: Value,
    in_multicall: bool,
    ip: Option<IpAddr>,
) -> RpcResponse {
    let Some(method) = canonical_method(raw_method, st.aria2_compat) else {
        // Unknown method: auth still runs first (the reference goes
        // through RpcMethod::execute -> authorize;
        // NoSuchMethodRpcMethod does not change that order), then "No
        // such method: <name>" (RpcMethodImpl.cc).
        if !token_gate(st, ip, &mut params).await {
            return RpcResponse::error(&RpcError::unauthorized(), id);
        }
        return RpcResponse::error(
            &RpcError::generic(format!("No such method: {raw_method}")),
            id,
        );
    };
    match method {
        "system.multicall" => {
            if in_multicall {
                // Recursion forbidden (RpcMethodImpl.cc); the check
                // comes before auth (the reference compares method names
                // inside the multicall loop, not via execute).
                return RpcResponse::error(
                    &RpcError::generic("Recursive system.multicall forbidden."),
                    id,
                );
            }
            process_multicall(st, params, id, ip).await
        }
        // system.list* is not authenticated: the reference overrides
        // execute to bypass authorize (RpcMethodImpl.cc). The
        // presentation face follows `--rpc-aria2-compat`.
        "system.listMethods" => RpcResponse::ok(list_of(method_face_names(st.aria2_compat)), id),
        "system.listNotifications" => RpcResponse::ok(
            list_of(notification_face(st.aria2_compat).iter().copied()),
            id,
        ),
        _ => {
            // All other methods: authorize first (the token
            // first-parameter strip, RpcMethod.cc), then dispatch.
            if !token_gate(st, ip, &mut params).await {
                return RpcResponse::error(&RpcError::unauthorized(), id);
            }
            // The write gate: with no secret the token layer is always
            // true, so the write face fails closed here (after auth,
            // before parameter decoding — a stable error priority).
            // Note: this is an authorization-semantics gate, not an auth
            // failure — it does not enter the backoff ledger.
            if st.secret().is_none() && !is_read_only(method) {
                return unauthenticated_write_error(id);
            }
            execute_session_method(st, method, params, id).await
        }
    }
}

#[cfg(test)]
mod tests;

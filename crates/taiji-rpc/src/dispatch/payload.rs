//! Unified single/batch payload handling: the entry shared by the HTTP
//! body and WS messages (moved verbatim from dispatch.rs; visibility
//! widened to pub(crate)).
//!
//! object = single call; array = batch (each element processed,
//! non-objects skipped, HTTP always 200, any unauthorized -> the whole
//! batch carries the deferred flag); anything else = Invalid Request.
//! The batch item cap [`super::MAX_BATCH_ITEMS`] rejects the whole
//! batch before per-item processing. `ip` = the transport-layer peer
//! address (auth-failure backoff ledger key; None = in-process test
//! surface).

use serde_json::Value;
use std::net::IpAddr;

use crate::aria2::error::RpcError;
use crate::jsonrpc::{ParsedCall, RpcResponse, parse_request};

use super::{AppState, process_call};

/// Unified handling of single/batch payloads (shared by the HTTP body
/// and WS messages). Returns the encoded response body + the code for
/// HTTP status selection + the deferred flag.
pub(crate) struct RpcOutcome {
    pub body: Value,
    pub code: i64,
    pub unauthorized: bool,
}

/// Item cap for batch arrays and system.multicall specs (security
/// fix): inside a 10MiB request, ~3.5×10⁶ `{}` items amplify to a
/// ~300MB response (26×); the 1000-item cap bounds the amplification
/// ratio; beyond it, answer the `taiji.request.too_many_items` string
/// code as an explicit error.
pub(crate) const MAX_BATCH_ITEMS: usize = 1000;

/// **Request-level total subcall cap** — a `system.multicall` inside
/// batch items is not counted by the recursion guard (the guard only
/// stops multicall inside multicall), so 1000 batch items × 1000
/// subcalls = 10⁶ full process_call runs (auth + session round trip
/// each) = an authenticated CPU/actor-occupancy DoS. The cap is 10_000
/// (= a fully-loaded legitimate multicall ×10 — normal clients stay
/// far below; aria2 has no such cap, an ecosystem gap this side
/// tightens).
pub(crate) const MAX_REQUEST_SUBCALLS: usize = 10_000;

/// Multicall expansion count of a batch item (preflight): for a
/// `system.multicall` item whose params[0] is an array, count its
/// length; otherwise 1.
fn item_subcall_count(item: &Value) -> usize {
    let Some(dict) = item.as_object() else {
        return 1;
    };
    if dict.get("method").and_then(Value::as_str) != Some("system.multicall") {
        return 1;
    }
    match dict
        .get("params")
        .and_then(Value::as_array)
        .and_then(|a| a.first())
    {
        Some(Value::Array(specs)) => specs.len().max(1),
        _ => 1,
    }
}

/// Over-cap items error (shared receipt for batch and multicall; the
/// message constructor lives in the adapter error table).
pub(crate) fn too_many_items(id: Value) -> RpcResponse {
    RpcResponse::error(&RpcError::too_many_items(MAX_BATCH_ITEMS), id)
}

pub(crate) async fn handle_payload(st: &AppState, v: &Value, ip: Option<IpAddr>) -> RpcOutcome {
    match v {
        Value::Object(_) => {
            let resp = single(st, v, ip).await;
            RpcOutcome {
                code: resp.code,
                unauthorized: resp.unauthorized,
                body: resp.encode(),
            }
        }
        Value::Array(items) => {
            // Item cap: reject the whole batch (a single error object,
            // not an array) — before per-item processing, to preclude
            // memory amplification.
            if items.len() > MAX_BATCH_ITEMS {
                let resp = too_many_items(Value::Null);
                return RpcOutcome {
                    code: resp.code,
                    unauthorized: false,
                    body: resp.encode(),
                };
            }
            // Request-level total subcall preflight — over-cap rejects
            // the whole batch (same shape as the item cap: before
            // per-item execution, precluding 10⁶-subcall
            // amplification).
            let total_subcalls: usize = items.iter().map(item_subcall_count).sum();
            if total_subcalls > MAX_REQUEST_SUBCALLS {
                let resp = RpcResponse::error(
                    &RpcError::subcall_budget_exceeded(total_subcalls, MAX_REQUEST_SUBCALLS),
                    Value::Null,
                );
                return RpcOutcome {
                    code: resp.code,
                    unauthorized: false,
                    body: resp.encode(),
                };
            }
            // Batch: process per element; skip non-object elements
            // (aria2 HttpServerBodyCommand.cc); the response is always
            // an array and HTTP is always 200 (a batch does not pick a
            // status code, sendJsonRpcBatchResponse); any unauthorized
            // -> the whole batch is deferred.
            let mut arr = Vec::with_capacity(items.len());
            let mut any_unauthorized = false;
            for item in items {
                if !item.is_object() {
                    continue;
                }
                let resp = single(st, item, ip).await;
                any_unauthorized |= resp.unauthorized;
                arr.push(resp.encode());
            }
            RpcOutcome {
                body: Value::Array(arr),
                code: 0,
                unauthorized: any_unauthorized,
            }
        }
        _ => {
            // Valid JSON but neither object nor array -> Invalid
            // Request (HttpServerBodyCommand.cc).
            let resp = match parse_request(v) {
                ParsedCall::ProtocolError(resp) => resp,
                ParsedCall::Request(_) => unreachable!("scalar cannot parse as request"),
            };
            RpcOutcome {
                code: resp.code,
                unauthorized: false,
                body: resp.encode(),
            }
        }
    }
}

pub(crate) async fn single(st: &AppState, v: &Value, ip: Option<IpAddr>) -> RpcResponse {
    match parse_request(v) {
        ParsedCall::Request(req) => {
            process_call(st, &req.method, req.params, req.id, false, ip).await
        }
        ParsedCall::ProtocolError(resp) => resp,
    }
}

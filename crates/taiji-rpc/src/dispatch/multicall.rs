//! system.multicall: RPC-layer expansion + the system.list* method
//! face (moved verbatim from dispatch.rs; visibility widened to
//! pub(crate)).
//!
//! Reference (RpcMethodImpl.cc): success is wrapped in a one-element
//! list / errors are inlined in place / recursion is forbidden (the
//! guard sits at the dispatch.rs entry, before auth); auth is pushed
//! down into the subcalls, and any unauthorized subcall -> the
//! deferred flag on the whole response. A multicall expands into
//! several `SessionHandle::call`s and never enters core.

use serde_json::{Value, json};
use std::net::IpAddr;

use crate::error::RpcError;
use crate::jsonrpc::RpcResponse;

use super::AppState;
use super::{MAX_BATCH_ITEMS, process_call, too_many_items};

/// system.multicall: RPC-layer expansion (cross-checked against
/// RpcMethodImpl.cc). `ip` = the transport-layer peer (auth is pushed
/// down into the subcalls; the backoff ledger key is passed through).
pub(crate) async fn process_multicall(
    st: &AppState,
    params: Vec<Value>,
    id: Value,
    ip: Option<IpAddr>,
) -> RpcResponse {
    // params[0] must be an array (checkRequiredParam<List>:
    // RpcMethodImpl.h).
    let specs = match params.first() {
        None => {
            return RpcResponse::error(
                &RpcError::generic("The parameter at 0 is required but missing."),
                id,
            );
        }
        Some(Value::Array(items)) => items,
        Some(_) => {
            return RpcResponse::error(
                &RpcError::generic("The parameter at 0 has wrong type."),
                id,
            );
        }
    };
    // Item cap: each spec expands into a subcall; without a cap a
    // 10MiB request could amplify to hundreds of MB of response;
    // over-cap rejects the whole call (after the checkRequiredParam
    // text surface, before any subcall executes).
    if specs.len() > MAX_BATCH_ITEMS {
        return too_many_items(id);
    }
    let mut results = Vec::with_capacity(specs.len());
    let mut any_unauthorized = false;
    for spec in specs {
        let Value::Object(dict) = spec else {
            results.push(inline_error("system.multicall expected struct."));
            continue;
        };
        let Some(Value::String(method_name)) = dict.get("methodName") else {
            results.push(inline_error("Missing methodName."));
            continue;
        };
        // params is optional; a non-array (including null/dict) is
        // treated as an empty list (the pop-or-empty semantics of
        // RpcMethodImpl.cc).
        let sub_params = match dict.get("params") {
            Some(Value::Array(items)) => items.clone(),
            _ => Vec::new(),
        };
        // Subcall id is null (RpcMethodImpl.cc's RpcRequest{nullptr
        // id}). Box::pin only breaks the compile-time process_call <->
        // process_multicall recursion; runtime recursion is rejected by
        // the guard above (a subcall system.multicall is not expanded).
        let res = Box::pin(process_call(
            st,
            method_name,
            sub_params,
            Value::Null,
            true,
            ip,
        ))
        .await;
        if res.unauthorized {
            any_unauthorized = true;
        }
        // Success wraps in a one-element list; errors inline in place
        // (RpcMethodImpl.cc).
        results.push(if res.code == 0 {
            json!([res.payload])
        } else {
            res.payload
        });
    }
    let mut resp = RpcResponse::ok(Value::Array(results), id);
    resp.unauthorized = any_unauthorized;
    resp
}

/// multicall inline error slot (shape = createErrorResponse:
/// RpcMethod.cc).
fn inline_error(message: &str) -> Value {
    json!({ "code": crate::error::CODE_GENERIC, "message": message })
}

/// list* response rendering (Item = `&str` bare names/event names or
/// `String` face-projected names).
pub(crate) fn list_of(items: impl IntoIterator<Item = impl Into<Value>>) -> Value {
    Value::Array(items.into_iter().map(Into::into).collect())
}

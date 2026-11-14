//! JSON-RPC parameter decoding helpers (moved verbatim from
//! dispatch.rs; visibility widened to `pub(crate)` for sibling reuse).
//!
//! Reference = the aria2 checkRequiredParam/checkParam shape
//! (RpcMethodImpl.h): standard texts for missing params / wrong types,
//! null/default semantics for optional items, and the same rule of
//! dropping non-string elements from string lists. The [`try_rpc`] macro
//! gives outer `-> RpcResponse` functions `?`-style error
//! short-circuiting.

use serde_json::Value;
use std::collections::BTreeMap;

use crate::aria2::error::RpcError;

// ---- parameter decoding helpers (reference = the checkRequiredParam/checkParam shape) ----

/// Standard error surface for missing params / wrong types (the
/// template texts live in the adapter error table —
/// [`RpcError::param_missing`] / [`RpcError::param_wrong_type`]).
pub(crate) fn param_error(index: usize, missing: bool) -> RpcError {
    if missing {
        RpcError::param_missing(index)
    } else {
        RpcError::param_wrong_type(index)
    }
}

pub(crate) fn required(params: &[Value], index: usize) -> Result<&Value, RpcError> {
    match params.get(index) {
        None | Some(Value::Null) => Err(param_error(index, true)),
        Some(v) => Ok(v),
    }
}

/// Optional string dict (the options surface); explicit null = not
/// given. Non-string values are skipped (aria2 gatherOption only
/// consumes String values, RpcMethod.cc).
pub(crate) fn opt_options(
    params: &[Value],
    index: usize,
) -> Result<BTreeMap<String, String>, RpcError> {
    match params.get(index) {
        None | Some(Value::Null) => Ok(BTreeMap::new()),
        Some(Value::Object(map)) => Ok(map
            .iter()
            .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
            .collect()),
        Some(_) => Err(param_error(index, false)),
    }
}

/// Optional integer position (the trailing parameter of
/// addUri/addTorrent/changeUri; RpcMethodImpl.cc checkPosParam:
/// null/missing = not given, negative = not given).
pub(crate) fn opt_position(params: &[Value], index: usize) -> Result<Option<usize>, RpcError> {
    match params.get(index) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(n)) => match n.as_i64() {
            Some(i) if i >= 0 => Ok(Some(i as usize)),
            _ => Ok(None),
        },
        Some(_) => Err(param_error(index, false)),
    }
}

/// GID parameter: passed down as the original string — every aria2 gid
/// parameter goes through `str2Gid` -> `GroupId::expandUnique` prefix
/// resolution on the method side (RpcMethodImpl.cc); prefix semantics
/// can only be decided inside core, which holds the full GID set; the
/// invalid/non-unique/not-found error surfaces are produced by the
/// actor direct translation ("Invalid GID %s" / "GID %s is not unique" /
/// "GID %s is not found").
pub(crate) fn gid_param(params: &[Value], index: usize) -> Result<String, RpcError> {
    match params.get(index) {
        None | Some(Value::Null) => Err(param_error(index, true)),
        Some(Value::String(s)) => Ok(s.clone()),
        Some(_) => Err(param_error(index, false)),
    }
}

/// Optional keys list (the trailing parameter of tellStatus/tell*;
/// non-string elements dropped — same rule as aria2 toStringList,
/// RpcMethodImpl.h).
pub(crate) fn opt_keys(params: &[Value], index: usize) -> Result<Vec<String>, RpcError> {
    match params.get(index) {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(items)) => Ok(items
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect()),
        Some(_) => Err(param_error(index, false)),
    }
}

/// Required integer (pagination offset/num; the
/// checkRequiredParam<Integer> text surface).
pub(crate) fn required_i64(params: &[Value], index: usize) -> Result<i64, RpcError> {
    match params.get(index) {
        None | Some(Value::Null) => Err(param_error(index, true)),
        Some(Value::Number(n)) => n.as_i64().ok_or_else(|| param_error(index, false)),
        Some(_) => Err(param_error(index, false)),
    }
}

/// Non-negative integer single value (a number or a numeric string —
/// the two-form convention for aria2 JSON numeric parameters, same rule
/// as banAddr minutes; negative/non-integer/over-bound = the wrong-type
/// text). `max` = the value-space upper bound (carrying the target's
/// width cap).
pub(crate) fn uint_value(v: &Value, index: usize, max: u64) -> Result<u64, RpcError> {
    let n = match v {
        Value::Number(n) => n.as_i64().ok_or_else(|| param_error(index, false))?,
        Value::String(s) => s
            .trim()
            .parse::<i64>()
            .map_err(|_| param_error(index, false))?,
        _ => return Err(param_error(index, false)),
    };
    if n < 0 {
        return Err(param_error(index, false));
    }
    u64::try_from(n)
        .ok()
        .filter(|&u| u <= max)
        .ok_or_else(|| param_error(index, false))
}

/// Required non-negative integer (the playback-head file/position
/// surface; missing param = the missing text).
pub(crate) fn uint_param(params: &[Value], index: usize, max: u64) -> Result<u64, RpcError> {
    match params.get(index) {
        None | Some(Value::Null) => Err(param_error(index, true)),
        Some(v) => uint_value(v, index, max),
    }
}

/// Pagination num validation (checkRequiredInteger(req, 1,
/// IntegerGE(0)), RpcMethodImpl.h: inner text + outer wrapper).
pub(crate) fn required_num(params: &[Value], index: usize) -> Result<i64, RpcError> {
    let v = required_i64(params, index)?;
    if v < 0 {
        return Err(RpcError::integer_param_not_ge_zero(index));
    }
    Ok(v)
}

/// String list (the uris surface; non-string elements dropped — same
/// rule as aria2 extractUris).
pub(crate) fn string_list(params: &[Value], index: usize) -> Result<Vec<String>, RpcError> {
    match required(params, index)? {
        Value::Array(items) => Ok(items
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect()),
        _ => Err(param_error(index, false)),
    }
}

/// Parameter-decode error short-circuit (the outer function returns
/// RpcResponse, not a Result — the macro substitutes for `?`).
macro_rules! try_rpc {
    ($id:expr, $e:expr) => {
        match $e {
            Ok(v) => v,
            Err(e) => return RpcResponse::error(&e, $id),
        }
    };
}

pub(crate) use try_rpc;

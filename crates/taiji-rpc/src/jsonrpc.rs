//! JSON-RPC 2.0 codec: request parsing + response/error shapes.
//!
//! Cross-checked against the read-only reference:
//! - Request parsing, branch by branch: `rpc_helper.cc`
//!   processJsonRpcRequest (missing id -> -32600; non-string method ->
//!   -32600; params absent -> empty; dict/named params -> -32602;
//!   explicit `params: null` also -> -32602);
//! - Response shape: `RpcResponse.cc` encodeJsonAll
//!   `{"id":..,"jsonrpc":"2.0","result"|"error":..}`;
//! - Error object shape: `RpcMethod.cc` (jsonRpc branch) `{code,message}`.
//!
//! Positional params only (aria2 does not support named params,
//! rpc_helper.cc "No support for Named params"); no XML-RPC.
//! The request's `jsonrpc` field is not consumed (aria2 the same:
//! processJsonRpcRequest never reads it; the response always carries
//! `"jsonrpc":"2.0"`).

use serde_json::{Map, Value, json};

use crate::aria2::error::RpcError;

/// A parsed single call (params is the positional array).
#[derive(Debug, Clone)]
pub struct RpcRequest {
    pub method: String,
    pub params: Vec<Value>,
    pub id: Value,
}

/// A JSON-RPC response. `payload` is the result value when code==0,
/// otherwise the error object `{code,message}`; `unauthorized` is the
/// deferred flag (consumed at the HTTP layer).
#[derive(Debug, Clone, PartialEq)]
pub struct RpcResponse {
    pub code: i64,
    pub payload: Value,
    pub id: Value,
    pub unauthorized: bool,
}

impl RpcResponse {
    pub fn ok(result: Value, id: Value) -> Self {
        RpcResponse {
            code: 0,
            payload: result,
            id,
            unauthorized: false,
        }
    }

    pub fn error(err: &RpcError, id: Value) -> Self {
        RpcResponse {
            code: err.code,
            payload: json!({ "code": err.code, "message": err.message }),
            id,
            unauthorized: err.unauthorized,
        }
    }

    /// Encode as the response object (key order cross-checked against
    /// encodeJsonAll: id -> jsonrpc -> result|error).
    pub fn encode(&self) -> Value {
        let mut m = Map::new();
        m.insert("id".to_string(), self.id.clone());
        m.insert("jsonrpc".to_string(), json!("2.0"));
        let slot = if self.code == 0 { "result" } else { "error" };
        m.insert(slot.to_string(), self.payload.clone());
        Value::Object(m)
    }
}

/// Single-request parse result: a valid call or a protocol-level error
/// response (error codes/texts cross-checked against rpc_helper.cc).
#[derive(Debug)]
pub enum ParsedCall {
    Request(RpcRequest),
    ProtocolError(RpcResponse),
}

/// Parse a single request object (branch-by-branch cross-check against
/// rpc_helper.cc).
pub fn parse_request(v: &Value) -> ParsedCall {
    let Value::Object(map) = v else {
        // Non-object top level (number/string/bool) -> Invalid Request
        // (id null). Reference: HttpServerBodyCommand.cc.
        return ParsedCall::ProtocolError(invalid_request(Value::Null));
    };
    // Missing id -> Invalid Request (id null) (rpc_helper.cc). An
    // explicit `"id": null` is legal: popValue yields a non-empty value
    // pointer for Null, and null is echoed.
    let Some(id) = map.get("id") else {
        return ParsedCall::ProtocolError(invalid_request(Value::Null));
    };
    let id = id.clone();
    // Non-string method -> Invalid Request (id echoed) (rpc_helper.cc).
    let Some(Value::String(method)) = map.get("method") else {
        return ParsedCall::ProtocolError(invalid_request(id));
    };
    // params: absent -> empty; array -> positional; anything else
    // (including explicit null / dict) -> -32602 Invalid params
    // (rpc_helper.cc).
    let params = match map.get("params") {
        None => Vec::new(),
        Some(Value::Array(items)) => items.clone(),
        Some(_) => {
            return ParsedCall::ProtocolError(invalid_params(id));
        }
    };
    ParsedCall::Request(RpcRequest {
        method: method.clone(),
        params,
        id,
    })
}

fn invalid_request(id: Value) -> RpcResponse {
    // Text/code cross-checked against rpc_helper.cc
    // createJsonRpcErrorResponse.
    RpcResponse::error(
        &RpcError {
            code: crate::aria2::error::CODE_INVALID_REQUEST,
            message: "Invalid Request.".to_string(),
            unauthorized: false,
        },
        id,
    )
}

fn invalid_params(id: Value) -> RpcResponse {
    RpcResponse::error(
        &RpcError {
            code: crate::aria2::error::CODE_INVALID_PARAMS,
            message: "Invalid params.".to_string(),
            unauthorized: false,
        },
        id,
    )
}

/// Protocol-level parse error (invalid JSON body): -32700 "Parse
/// error.", id null (HttpServerBodyCommand.cc).
pub fn parse_error_response() -> RpcResponse {
    RpcResponse::error(
        &RpcError {
            code: crate::aria2::error::CODE_PARSE_ERROR,
            message: "Parse error.".to_string(),
            unauthorized: false,
        },
        Value::Null,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aria2::error::{CODE_INVALID_PARAMS, CODE_INVALID_REQUEST, CODE_PARSE_ERROR};

    #[test]
    fn parses_positional_request_and_echoes_id() {
        let v = json!({"jsonrpc": "2.0", "id": 7, "method": "getVersion", "params": ["token:x"]});
        match parse_request(&v) {
            ParsedCall::Request(req) => {
                assert_eq!(req.method, "getVersion");
                assert_eq!(req.params, vec![json!("token:x")]);
                assert_eq!(req.id, json!(7));
            }
            other => panic!("expected request, got {other:?}"),
        }
    }

    #[test]
    fn absent_params_means_empty_but_null_params_is_invalid() {
        let absent = json!({"id": 1, "method": "getVersion"});
        assert!(matches!(parse_request(&absent), ParsedCall::Request(_)));

        let null_params = json!({"id": 1, "method": "getVersion", "params": null});
        match parse_request(&null_params) {
            ParsedCall::ProtocolError(resp) => {
                assert_eq!(resp.code, CODE_INVALID_PARAMS);
                assert_eq!(resp.payload["message"], "Invalid params.");
                assert_eq!(resp.id, json!(1));
            }
            other => panic!("expected protocol error, got {other:?}"),
        }
    }

    #[test]
    fn missing_id_and_non_string_method_are_invalid_request() {
        let no_id = json!({"method": "getVersion"});
        match parse_request(&no_id) {
            ParsedCall::ProtocolError(resp) => {
                assert_eq!(resp.code, CODE_INVALID_REQUEST);
                assert_eq!(resp.id, Value::Null);
            }
            other => panic!("expected protocol error, got {other:?}"),
        }

        let bad_method = json!({"id": 2, "method": 42});
        match parse_request(&bad_method) {
            ParsedCall::ProtocolError(resp) => {
                assert_eq!(resp.code, CODE_INVALID_REQUEST);
                assert_eq!(resp.id, json!(2));
            }
            other => panic!("expected protocol error, got {other:?}"),
        }
    }

    #[test]
    fn scalar_top_level_is_invalid_request() {
        // HttpServerBodyCommand.cc: valid JSON but not a dict/list.
        match parse_request(&json!(42)) {
            ParsedCall::ProtocolError(resp) => assert_eq!(resp.code, CODE_INVALID_REQUEST),
            other => panic!("expected protocol error, got {other:?}"),
        }
    }

    #[test]
    fn encode_shape_matches_encode_json_all() {
        // Key set cross-checked against RpcResponse.cc; success ->
        // result, failure -> error.
        let ok = RpcResponse::ok(json!({"version": "taiji/0.1.0"}), json!(1)).encode();
        assert_eq!(ok["id"], json!(1));
        assert_eq!(ok["jsonrpc"], "2.0");
        assert!(ok.get("error").is_none());
        assert_eq!(ok["result"]["version"], "taiji/0.1.0");

        let err = RpcResponse::error(&RpcError::unauthorized(), Value::Null).encode();
        assert_eq!(err["jsonrpc"], "2.0");
        assert!(err.get("result").is_none());
        assert_eq!(err["error"]["code"], 1);
        assert_eq!(err["error"]["message"], "Unauthorized");
    }

    #[test]
    fn parse_error_response_shape() {
        let resp = parse_error_response();
        assert_eq!(resp.code, CODE_PARSE_ERROR);
        assert_eq!(resp.payload["message"], "Parse error.");
        assert_eq!(resp.id, Value::Null);
    }
}

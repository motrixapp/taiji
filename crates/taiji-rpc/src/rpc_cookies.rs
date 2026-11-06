//! Task-cookie direct-pass parameter parsing (shared seam by
//! taiji.addUriWithCookies / taiji.setTaskCookies).
//!
//! Validation order and error texts mirror
//! `RpcCookie.cc parseRpcCookies` verbatim; the full rule list:
//! Upstream anchor mapping: docs/design/rpc.md
//!
//! Error shape: DL_ABORT_EX texts flow through [`RpcError::generic`]
//! as numeric code 1 + original text (the same mapping chain as
//! method-body errors).

use serde_json::Value;

use taiji_core::session::TaskCookieSpec;

use crate::dispatch::params::{param_error, required};
use crate::error::RpcError;

/// `expiresAt` value-space upper bound (RpcCookie.cc
/// `9007199254740991LL` = 2^53-1, the JSON safe-integer domain).
const MAX_EXPIRES_AT_MS: i64 = 9_007_199_254_740_991;

/// Cookie array cap (RpcCookie.cc `cookies.size() > 300`).
const MAX_TASK_COOKIES: usize = 300;

/// Parse the cookies array at parameter position `index` -> task cookie
/// specs (validation order and error texts mirror RpcCookie.cc
/// parseRpcCookies verbatim — module-doc anchor).
pub(crate) fn parse_task_cookies(
    params: &[Value],
    index: usize,
) -> Result<Vec<TaskCookieSpec>, RpcError> {
    let items = match required(params, index)? {
        Value::Array(items) => items,
        _ => return Err(param_error(index, false)),
    };
    if items.len() > MAX_TASK_COOKIES {
        return Err(RpcError::generic("Too many task cookies."));
    }
    let mut out = Vec::with_capacity(items.len());
    for entry in items {
        let object = match entry {
            Value::Object(map) => map,
            _ => return Err(RpcError::generic("Task cookie must be an object.")),
        };
        // Field whitelist (unknown fields rejected explicitly — same
        // rule as the fork, never silently ignored).
        for key in object.keys() {
            if !matches!(
                key.as_str(),
                "name"
                    | "value"
                    | "domain"
                    | "path"
                    | "hostOnly"
                    | "secure"
                    | "httpOnly"
                    | "expiresAt"
            ) {
                return Err(RpcError::generic("Unknown task cookie field."));
            }
        }
        // ok_or_else (not ok_or): the error is allocated lazily — the
        // happy path must not build the RpcError text.
        let name = string_field(object, "name")?.ok_or_else(string_field_error)?;
        let value = string_field(object, "value")?.ok_or_else(string_field_error)?;
        let domain_raw = string_field(object, "domain")?.ok_or_else(string_field_error)?;
        let path = string_field(object, "path")?.unwrap_or_else(|| "/".to_string());
        // Syntax checks (same form and order as the fork).
        if name.is_empty()
            || name.len() + value.len() > 4096
            || domain_raw.is_empty()
            || domain_raw.len() > 254
            || path.len() > 4096
            || !safe_value(&value)
            || !safe_value(&path)
            || !good_path(&path)
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
        {
            return Err(RpcError::generic("Invalid task cookie syntax."));
        }
        // hostOnly default = domain without a leading dot; strip the
        // leading dot and canonicalize to lowercase.
        let mut host_only = bool_field(object, "hostOnly", !domain_raw.starts_with('.'))?;
        let domain = domain_raw
            .strip_prefix('.')
            .unwrap_or(&domain_raw)
            .to_ascii_lowercase();
        let numeric = domain.parse::<std::net::IpAddr>().is_ok();
        if numeric {
            // Numeric hosts force host-only (`hostOnly || numeric`).
            host_only = true;
        }
        // Domain checks (verbatim text): empty / double dots / leading
        // or trailing dot / illegal characters (non-numeric hosts
        // limited to [a-z0-9-.]).
        if domain.is_empty()
            || domain.contains("..")
            || domain.starts_with('.')
            || domain.ends_with('.')
            || (!numeric
                && !domain.bytes().all(|b| {
                    b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.'
                }))
        {
            return Err(RpcError::generic("Invalid task cookie domain."));
        }
        // expiresAt: optional non-negative Unix milliseconds <= 2^53-1
        // (verbatim text); the second conversion = integer-division
        // truncation. Default = session cookie.
        let expires_utc = match object.get("expiresAt") {
            None | Some(Value::Null) => None,
            Some(v) => {
                let ms = v.as_i64().ok_or_else(expires_error)?;
                if !(0..=MAX_EXPIRES_AT_MS).contains(&ms) {
                    return Err(expires_error());
                }
                Some(ms / 1000)
            }
        };
        out.push(TaskCookieSpec {
            name,
            value,
            domain,
            path,
            host_only,
            secure: bool_field(object, "secure", false)?,
            http_only: bool_field(object, "httpOnly", false)?,
            expires_utc,
        });
    }
    Ok(out)
}

/// "Task cookie expiry must be nonnegative Unix milliseconds."
/// (RpcCookie.cc verbatim).
fn expires_error() -> RpcError {
    RpcError::generic("Task cookie expiry must be nonnegative Unix milliseconds.")
}

/// "Invalid task cookie string field." (RpcCookie.cc verbatim).
fn string_field_error() -> RpcError {
    RpcError::generic("Invalid task cookie string field.")
}

/// String field extraction (same rule as the fork `stringField`): a
/// required key missing, or present but not a string = "Invalid task
/// cookie string field."; an optional key missing = `Ok(None)`.
fn string_field(
    object: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<Option<String>, RpcError> {
    match object.get(key) {
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(string_field_error()),
        None => Ok(None),
    }
}

/// Boolean field extraction (same rule as the fork `boolField`):
/// missing = fallback; present but not a bool = "Invalid task cookie
/// boolean field.".
fn bool_field(
    object: &serde_json::Map<String, Value>,
    key: &str,
    fallback: bool,
) -> Result<bool, RpcError> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(fallback),
        Some(Value::Bool(b)) => Ok(*b),
        Some(_) => Err(RpcError::generic("Invalid task cookie boolean field.")),
    }
}

/// safeValue: no CTL (<0x20), no DEL (0x7f), no `;` — the Cookie header
/// injection surface (path checked the same way).
fn safe_value(value: &str) -> bool {
    !value.bytes().any(|b| b < 0x20 || b == 0x7f || b == b';')
}

/// goodPath (cookie_helper.cc): non-empty and starting with `/`.
fn good_path(path: &str) -> bool {
    path.starts_with('/')
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn parse(v: Value) -> Result<Vec<TaskCookieSpec>, RpcError> {
        parse_task_cookies(&[json!([]), v], 1)
    }

    /// Legal shapes: full-field and default shapes (path/hostOnly/
    /// secure/httpOnly/expiresAt defaulted) both arms; the
    /// millisecond->second conversion asserted.
    #[test]
    fn parses_full_and_default_shapes() {
        let full = parse(json!([{
            "name": "sid", "value": "abc123", "domain": ".Example.COM",
            "path": "/deep", "hostOnly": false, "secure": true,
            "httpOnly": true, "expiresAt": 4102444800123i64
        }]))
        .unwrap_or_else(|e| panic!("full: {e:?}"));
        assert_eq!(full.len(), 1);
        let c = &full[0];
        assert_eq!(
            c.domain, "example.com",
            "leading dot stripped + lowercase canonical form"
        );
        assert!(!c.host_only);
        assert!(c.secure && c.http_only);
        assert_eq!(c.path, "/deep");
        assert_eq!(
            c.expires_utc,
            Some(4102444800),
            "millisecond -> second truncating integer division"
        );

        let bare = parse(json!([{"name": "k", "value": "v", "domain": "127.0.0.1"}]))
            .unwrap_or_else(|e| panic!("bare: {e:?}"));
        let c = &bare[0];
        assert_eq!(c.path, "/");
        assert!(c.host_only, "a numeric host forces host-only");
        assert_eq!(c.expires_utc, None, "absent expiry = a session cookie");
        assert!(!c.secure && !c.http_only);
    }

    /// Structural rejection surface (verbatim fork texts): over-cap /
    /// non-object / unknown field / string and boolean type errors /
    /// syntax checks / domain checks / expiry value space.
    #[test]
    fn rejects_fork_verbatim() {
        let many: Vec<Value> = (0..301)
            .map(|i| json!({"name": format!("n{i}"), "value": "v", "domain": "a.com"}))
            .collect();
        assert_eq!(err(parse(json!(many))), "Too many task cookies.");
        assert_eq!(
            err(parse(json!(["not-an-object"]))),
            "Task cookie must be an object."
        );
        assert_eq!(
            err(parse(
                json!([{"name": "k", "value": "v", "domain": "a.com", "extra": 1}])
            )),
            "Unknown task cookie field."
        );
        assert_eq!(
            err(parse(json!([{"name": "k", "domain": "a.com"}]))),
            "Invalid task cookie string field.",
            "value absent"
        );
        assert_eq!(
            err(parse(json!([{"name": 1, "value": "v", "domain": "a.com"}]))),
            "Invalid task cookie string field.",
            "name not a string"
        );
        assert_eq!(
            err(parse(
                json!([{"name": "k", "value": "v", "domain": "a.com", "secure": "yes"}])
            )),
            "Invalid task cookie boolean field."
        );
        // Syntax checks: empty name / illegal token character / name+
        // value over 4096 / value containing ';' / path not starting
        // with '/'.
        assert_eq!(
            err(parse(
                json!([{"name": "", "value": "v", "domain": "a.com"}])
            )),
            "Invalid task cookie syntax."
        );
        assert_eq!(
            err(parse(
                json!([{"name": "a b", "value": "v", "domain": "a.com"}])
            )),
            "Invalid task cookie syntax."
        );
        let long: String = "x".repeat(4097);
        assert_eq!(
            err(parse(
                json!([{"name": "k", "value": long, "domain": "a.com"}])
            )),
            "Invalid task cookie syntax."
        );
        assert_eq!(
            err(parse(
                json!([{"name": "k", "value": "a;b", "domain": "a.com"}])
            )),
            "Invalid task cookie syntax."
        );
        assert_eq!(
            err(parse(
                json!([{"name": "k", "value": "v", "domain": "a.com", "path": "noslash"}])
            )),
            "Invalid task cookie syntax."
        );
        // Domain checks: double dots / leading and trailing dots /
        // illegal character / empty.
        assert_eq!(
            err(parse(
                json!([{"name": "k", "value": "v", "domain": "a..com"}])
            )),
            "Invalid task cookie domain."
        );
        assert_eq!(
            err(parse(
                json!([{"name": "k", "value": "v", "domain": ".a.com."}])
            )),
            "Invalid task cookie domain."
        );
        assert_eq!(
            err(parse(
                json!([{"name": "k", "value": "v", "domain": "a_com"}])
            )),
            "Invalid task cookie domain."
        );
        assert_eq!(
            err(parse(json!([{"name": "k", "value": "v", "domain": "."}]))),
            "Invalid task cookie domain."
        );
        // expiry: negative / non-integer / over 2^53-1 verbatim text;
        // boundary values accepted.
        assert_eq!(
            err(parse(
                json!([{"name": "k", "value": "v", "domain": "a.com", "expiresAt": -1}])
            )),
            "Task cookie expiry must be nonnegative Unix milliseconds."
        );
        assert_eq!(
            err(parse(
                json!([{"name": "k", "value": "v", "domain": "a.com", "expiresAt": 1.5}])
            )),
            "Task cookie expiry must be nonnegative Unix milliseconds."
        );
        assert_eq!(
            err(parse(json!([
                {"name": "k", "value": "v", "domain": "a.com", "expiresAt": 9_007_199_254_740_992i64}
            ]))),
            "Task cookie expiry must be nonnegative Unix milliseconds."
        );
        let edge = parse(json!([
            {"name": "k", "value": "v", "domain": "a.com", "expiresAt": 0},
            {"name": "m", "value": "v", "domain": "b.com", "expiresAt": 9_007_199_254_740_991i64}
        ]))
        .unwrap_or_else(|e| panic!("edge: {e:?}"));
        assert_eq!(edge[0].expires_utc, Some(0));
        assert_eq!(edge[1].expires_utc, Some(MAX_EXPIRES_AT_MS / 1000));
    }

    /// Parameter-position shape: cookies missing / non-array = standard
    /// parameter texts (not fork-specific — the checkRequiredParam<List>
    /// template surface).
    #[test]
    fn param_face() {
        let r = parse_task_cookies(&[json!("g")], 1);
        assert_eq!(err(r), "The parameter at 1 is required but missing.");
        let r = parse_task_cookies(&[json!("g"), json!("nope")], 1);
        assert_eq!(err(r), "The parameter at 1 has wrong type.");
    }

    fn err(r: Result<Vec<TaskCookieSpec>, RpcError>) -> String {
        match r {
            Err(e) => e.message,
            Ok(_) => panic!("expected parse error"),
        }
    }
}

//! The three segmentation traits and their supporting types live in
//! taiji-segment since the verbatim lift (the vocabulary
//! crate: vocabulary at the bottom, engines as siblings, session on
//! top — sibling engines must not depend on this HTTP crate for the
//! segment vocabulary). This module is the path-stable transition
//! face re-exporting them, plus the HTTP-only free function
//! [`same_origin`] that stayed behind (reqwest-coupled; the
//! upstream-anchor design notes moved with the traits:
//! docs/design/http.md and taiji-segment/src/traits.rs).

pub use taiji_segment::traits::*;

/// Endpoint same-origin verdict (`scheme://host:port` — the same
/// dimension as the per-host cap's host_key; a parse failure is
/// conservatively treated as different-origin — the caller falls back
/// to the original face, behaving as if the face were absent). Used
/// by the start-URL credential-scope decision
/// ([`crate::transport::HttpRangeTransport::request_uri`]).
pub fn same_origin(a: &str, b: &str) -> bool {
    match (reqwest::Url::parse(a), reqwest::Url::parse(b)) {
        (Ok(a), Ok(b)) => {
            a.scheme() == b.scheme()
                && a.host_str() == b.host_str()
                && a.port_or_known_default() == b.port_or_known_default()
        }
        _ => false,
    }
}

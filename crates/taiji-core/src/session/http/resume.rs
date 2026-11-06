//! ResumeValidator decision table ("signature-stream friendly") — pure
//! functions, no IO.
//!
//! Decision order (first match wins; rationale in the branch comments):
//! 1. **path** (compared after stripping query/fragment) — a signature
//! URL's query drifts on every fetch; the path is the resource
//! location fact;
//! 2. **encoding** — with `Content-Encoding != identity` the Range
//! semantics are unknowable and the bitmap is not enabled; if either
//! side fails, there is nothing to resume from;
//! 3. **length** — the authoritative total must be present and equal on
//! both sides; a missing side = no authoritative length (the
//! no-bitmap shape), never resume;
//! 4. **strong validators**: strong ETag first, Last-Modified fallback
//! — both present and equal -> strong resume; both present but
//! unequal -> from zero; **a one-sided strong ETag** (the peer once
//! sent a strong validator and it is missing now, or vice versa) ->
//! the Last-Modified **fallback decision**: LM match = strong
//! resume, unequal / undecidable = from zero `EtagMismatch` — never
//! degrade to a weak resume (the server has proven it sends strong
//! validators; a missing one makes the resource suspect);
//! 5. **neither** (strong ETag and Last-Modified missing on both
//! sides) but path+length match -> weak resume
//! (`ResumeBasis::PathOnly`).
//!
//! **One-sided asymmetry (a recorded decision)**: a strong ETag on one
//! side -> the LM fallback (step 4, possibly a strong resume); LM on
//! one side (no ETag) -> `Undecidable` -> weak resume (step 5). The
//! asymmetry is intentional: an ETag is a strong validator and its
//! one-sided drift is a stronger signal that must be decided by another
//! strong face (LM); a one-sided missing LM is not evidence of a
//! suspect resource (LM routinely disappears behind cache layers).
//!
//! A weak ETag (`W/` prefix) counts as missing on both the payload and
//! the decision side ([`strong_etag`]) — a weak tag promises no
//! byte-level identity and cannot back a strong validation.
//!
//! The decision-table inputs correspond field by name with the
//! `ResumeValidator` in the frozen taiji-http seam
//! (`SegmentSource::validator`'s return face); under the crate topology
//! constraint (core does not depend on taiji-http) this module holds an
//! isomorphic mirror, moved field by field at wiring time — the single
//! source of decision semantics is this table.
//!
//! Upstream anchor mapping: docs/design/core.md

use sha2::{Digest as _, Sha256};

/// Resume-validation payload (the persisted shape recorded by the
/// probe; field by field).
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ValidatorFacts {
    /// The final URL's normalized path (path only, query stripped;
    /// accepts a raw URL argument — idempotently normalized at decision
    /// time, see [`url_path`]).
    pub final_url_path: String,
    /// Authoritative total length (the TOTAL of a probe 206 +
    /// `Content-Range: bytes 0-0/TOTAL`; None = the no-length shape —
    /// no bitmap, restore always from zero).
    #[serde(default)]
    pub total_len: Option<u64>,
    /// Strong ETag only; `W/` weak tags count as missing
    /// ([`strong_etag`]).
    #[serde(default)]
    pub etag: Option<String>,
    /// Last-Modified verbatim.
    #[serde(default)]
    pub last_modified: Option<String>,
    /// Response encoding confirmed identity (false = the bitmap is not
    /// enabled).
    #[serde(default)]
    pub encoding_ok: bool,
}

impl ValidatorFacts {
    /// Canonical bytes (deterministic serialization — fields in a fixed
    /// order, serde struct order), the sole input to the digest.
    /// **Version prefix**: when the payload fields evolve, the prefix
    /// changes with them, so an old digest never mismatches a
    /// new-format payload (a restore-time comparison failure = from
    /// zero, the safe direction). Serialization failures propagate
    /// explicitly (an `unwrap_or_default` would fold a failure into an
    /// "empty payload constant digest" — the decision face would see a
    /// missing validator, a disguised degradation).
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        const CANONICAL_VERSION: &[u8] = b"taiji/validator-facts/v1\n";
        let mut out = CANONICAL_VERSION.to_vec();
        serde_json::to_writer(&mut out, self)?;
        Ok(out)
    }
}

/// The ResumeValidator payload digest (the producer face of
/// `http_task.validator_digest`): SHA-256(canonical bytes, including
/// the format version prefix). The store only stores bytes; validation
/// semantics belong to this module — recomputing and comparing at
/// restore time detects a tampered / stale payload. Serialization
/// failures propagate explicitly; the caller treats them as a missing
/// validator.
pub fn validator_digest(facts: &ValidatorFacts) -> Result<Vec<u8>, serde_json::Error> {
    Ok(Sha256::digest(facts.canonical_bytes()?).to_vec())
}

/// The URL path after stripping query/fragment (idempotent: a path
/// argument passes through unchanged).
///
/// **Accepted input grammar** (a signature contract; a hand-written
/// byte scan, not the full RFC 3986 grammar):
/// - absolute URL: `scheme://authority/path?query#fragment` (scheme =
/// any non-empty string; the authority ends at the first `/`) —
/// `http://h/f.bin?sig=x` -> `/f.bin`;
/// - an already-stripped origin-form path: `/path?query#fragment` —
/// `/f.bin?x=1` -> `/f.bin`;
/// - an empty path (`http://h` or `http://h?q=1`) -> `/`.
///
/// Semantic boundary (the comparison is a **byte-level** path match):
/// no %-decoding normalization (`/a%2Fb` and `/a/b` are different
/// resources — the conservative direction: an extra path-drift verdict
/// only causes an extra from-zero, never a wrong resume), no
/// IDN/host parsing, no `..` segment handling. Inputs outside this
/// grammar (e.g. a `scheme:opaque` form with no authority) are
/// processed byte-by-byte as origin-form paths, with no semantic
/// guarantee.
pub fn url_path(raw: &str) -> &str {
    let no_fragment = match raw.find('#') {
        Some(i) => &raw[..i],
        None => raw,
    };
    // scheme://authority/path — the first '/' after the authority is
    // the path start.
    let after_authority = match no_fragment.find("://") {
        Some(scheme_end) => {
            let rest = &no_fragment[scheme_end + 3..];
            match rest.find('/') {
                Some(i) => &rest[i..],
                None => "/",
            }
        }
        None => no_fragment,
    };
    match after_authority.find('?') {
        Some(i) => &after_authority[..i],
        None => after_authority,
    }
}

/// Strong ETag normalization: trim whitespace; a `W/` prefix (weak tag,
/// RFC 7232 §2.1) or an empty string -> None (counted as missing).
pub fn strong_etag(raw: Option<&str>) -> Option<String> {
    let trimmed = raw?.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.len() >= 2 && trimmed.starts_with("W/") {
        return None;
    }
    Some(trimmed.to_string())
}

/// The comparison basis for strong validation (strong = an ETag /
/// Last-Modified hit; weak = path+length only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResumeBasis {
    /// ETag or Last-Modified matched (a strong validator hit).
    Validator,
    /// No strong validator on either side, path+length only (the
    /// signature-stream norm).
    PathOnly,
}

/// Why the decision is restart-from-zero (observation face: restore
/// reports / logs; never persisted into the row).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestartReason {
    /// path mismatch (the resource location drifted).
    PathMismatch,
    /// Either side's encoding is not identity (the bitmap is not
    /// enabled).
    EncodingNotIdentity,
    /// The authoritative total is missing or unequal (the `.part` reuse
    /// decision: a length mismatch re-downloads wholesale).
    LengthMismatch,
    /// Strong ETag mismatch or one-sided missing.
    EtagMismatch,
    /// Last-Modified mismatch or one-sided missing (the fallback face
    /// when ETag is unusable).
    LastModifiedMismatch,
}

/// The decision (the decision table's three exits).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResumeDecision {
    /// Resume (the bitmap is valid; `basis` marks strong/weak — a weak
    /// resume exposes the `weak` semantics in the http sub-dictionary).
    Resume { basis: ResumeBasis },
    /// From zero (the bitmap is cleared; the `restarted` semantics).
    Restart { reason: RestartReason },
}

/// The decision-table body: `stored` = the persisted payload (the last
/// probe record), `fresh` = this probe's record. Both sides are
/// idempotently normalized (path query stripped, weak ETags stripped).
pub fn decide_resume(stored: &ValidatorFacts, fresh: &ValidatorFacts) -> ResumeDecision {
    // 1. path (the query drifts on every fetch — only after stripping
    // is it the resource-location fact).
    if url_path(&stored.final_url_path) != url_path(&fresh.final_url_path) {
        return ResumeDecision::Restart {
            reason: RestartReason::PathMismatch,
        };
    }
    // 2. encoding: either side not identity -> Range semantics
    // unknowable, no bitmap.
    if !stored.encoding_ok || !fresh.encoding_ok {
        return ResumeDecision::Restart {
            reason: RestartReason::EncodingNotIdentity,
        };
    }
    // 3. length: the authoritative total present and equal on both
    // sides; a missing side = the no-bitmap shape.
    if stored.total_len.is_none() || fresh.total_len != stored.total_len {
        return ResumeDecision::Restart {
            reason: RestartReason::LengthMismatch,
        };
    }
    // 4. strong validators: ETag first, Last-Modified fallback;
    // one-sided presence = drift, from zero.
    let (se, fe) = (
        strong_etag(stored.etag.as_deref()),
        strong_etag(fresh.etag.as_deref()),
    );
    match (se, fe) {
        (Some(s), Some(f)) if s == f => {
            return ResumeDecision::Resume {
                basis: ResumeBasis::Validator,
            };
        }
        (Some(_), Some(_)) => {
            return ResumeDecision::Restart {
                reason: RestartReason::EtagMismatch,
            };
        }
        (None, None) => {}
        // One-sided strong ETag: the server has proven it sends
        // validators, so a missing one now = a suspect resource (never
        // degrade to a weak resume); decide via the Last-Modified
        // fallback.
        _ => {
            return match last_modified_pair(stored, fresh) {
                LastModified::Match => ResumeDecision::Resume {
                    basis: ResumeBasis::Validator,
                },
                LastModified::Mismatch | LastModified::Undecidable => ResumeDecision::Restart {
                    reason: RestartReason::EtagMismatch,
                },
            };
        }
    }
    // No strong ETag on either side -> the Last-Modified decision.
    match last_modified_pair(stored, fresh) {
        LastModified::Match => ResumeDecision::Resume {
            basis: ResumeBasis::Validator,
        },
        LastModified::Mismatch => ResumeDecision::Restart {
            reason: RestartReason::LastModifiedMismatch,
        },
        // Neither side but path+length match (already passed above) ->
        // weak resume.
        LastModified::Undecidable => ResumeDecision::Resume {
            basis: ResumeBasis::PathOnly,
        },
    }
}

enum LastModified {
    Match,
    Mismatch,
    Undecidable,
}

fn last_modified_pair(stored: &ValidatorFacts, fresh: &ValidatorFacts) -> LastModified {
    match (
        stored.last_modified.as_deref(),
        fresh.last_modified.as_deref(),
    ) {
        (Some(s), Some(f)) if s.trim() == f.trim() => LastModified::Match,
        (Some(_), Some(_)) => LastModified::Mismatch,
        _ => LastModified::Undecidable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test-only Result unwrap (unwrap/expect are lint-forbidden).
    fn ok<T, E: std::fmt::Display>(r: Result<T, E>, what: &str) -> T {
        match r {
            Ok(v) => v,
            Err(e) => panic!("{what}: {e}"),
        }
    }

    fn facts(path: &str, total: u64, etag: Option<&str>, lm: Option<&str>) -> ValidatorFacts {
        ValidatorFacts {
            final_url_path: path.into(),
            total_len: Some(total),
            etag: etag.map(str::to_string),
            last_modified: lm.map(str::to_string),
            encoding_ok: true,
        }
    }

    fn resumed(d: ResumeDecision) -> ResumeBasis {
        match d {
            ResumeDecision::Resume { basis } => basis,
            ResumeDecision::Restart { reason } => panic!("expected resume, got restart {reason:?}"),
        }
    }

    fn restart(d: ResumeDecision) -> RestartReason {
        match d {
            ResumeDecision::Restart { reason } => reason,
            ResumeDecision::Resume { basis } => panic!("expected restart, got resume {basis:?}"),
        }
    }

    /// Strong ETag hit -> strong resume; a length mismatch overrides an
    /// ETag hit; an ETag mismatch restarts.
    #[test]
    fn strong_etag_table() {
        let stored = facts("/f.bin", 100, Some("\"abc\""), None);
        // Hit.
        assert_eq!(
            resumed(decide_resume(
                &stored,
                &facts("/f.bin", 100, Some("\"abc\""), None)
            )),
            ResumeBasis::Validator
        );
        // Mismatch -> from zero (even with equal lengths).
        assert_eq!(
            restart(decide_resume(
                &stored,
                &facts("/f.bin", 100, Some("\"def\""), None)
            )),
            RestartReason::EtagMismatch
        );
        // ETag hit but lengths differ -> from zero.
        assert_eq!(
            restart(decide_resume(
                &stored,
                &facts("/f.bin", 200, Some("\"abc\""), None)
            )),
            RestartReason::LengthMismatch
        );
    }

    /// Weak ETag (W/) counts as missing: W/ on both sides -> degrades to
    /// a weak resume; W/ on one side and a strong tag on the other ->
    /// the validator drifted, from zero; W/ on one side with no
    /// fallback face -> from zero (the server once sent an ETag, so a
    /// missing one is suspect — no weak resume).
    #[test]
    fn weak_etag_treated_as_missing() {
        // W/ both sides, same value: both count as missing -> path+
        // length match -> weak resume.
        let weak_stored = facts("/f.bin", 100, Some("W/\"abc\""), None);
        assert_eq!(
            resumed(decide_resume(
                &weak_stored,
                &facts("/f.bin", 100, Some("W/\"abc\""), None)
            )),
            ResumeBasis::PathOnly
        );
        // stored weak (-> missing), fresh strong: one-sided strong ->
        // no fallback face -> from zero.
        assert_eq!(
            restart(decide_resume(
                &weak_stored,
                &facts("/f.bin", 100, Some("\"abc\""), None)
            )),
            RestartReason::EtagMismatch
        );
        // stored strong, fresh weak (-> missing): from zero as above.
        let strong_stored = facts("/f.bin", 100, Some("\"abc\""), None);
        assert_eq!(
            restart(decide_resume(
                &strong_stored,
                &facts("/f.bin", 100, Some("W/\"abc\""), None)
            )),
            RestartReason::EtagMismatch
        );
        // One-sided strong + Last-Modified matching on both sides ->
        // fallback strong resume (the strong validator decided by LM);
        // LM unequal -> from zero.
        let lm = "Mon, 01 Jan 2024 00:00:00 GMT";
        let strong_with_lm = facts("/f.bin", 100, Some("\"abc\""), Some(lm));
        assert_eq!(
            resumed(decide_resume(
                &strong_with_lm,
                &facts("/f.bin", 100, Some("W/\"abc\""), Some(lm))
            )),
            ResumeBasis::Validator
        );
        assert_eq!(
            restart(decide_resume(
                &strong_with_lm,
                &facts(
                    "/f.bin",
                    100,
                    Some("W/\"abc\""),
                    Some("Tue, 02 Jan 2024 00:00:00 GMT")
                )
            )),
            RestartReason::EtagMismatch
        );
        // One-sided strong + the peer's LM missing (undecidable) ->
        // from zero.
        assert_eq!(
            restart(decide_resume(
                &strong_with_lm,
                &facts("/f.bin", 100, Some("W/\"abc\""), None)
            )),
            RestartReason::EtagMismatch
        );
    }

    /// Last-Modified fallback face: with no ETag on either side, a hit
    /// -> strong resume, unequal -> from zero; a one-sided LM
    /// (undecidable) -> weak resume (the path+length facts still hold).
    #[test]
    fn last_modified_fallback_table() {
        let stored = facts("/f.bin", 100, None, Some("Mon, 01 Jan 2024 00:00:00 GMT"));
        assert_eq!(
            resumed(decide_resume(
                &stored,
                &facts("/f.bin", 100, None, Some("Mon, 01 Jan 2024 00:00:00 GMT"))
            )),
            ResumeBasis::Validator
        );
        assert_eq!(
            restart(decide_resume(
                &stored,
                &facts("/f.bin", 100, None, Some("Tue, 02 Jan 2024 00:00:00 GMT"))
            )),
            RestartReason::LastModifiedMismatch
        );
        // No validator on either side -> weak resume.
        let bare = facts("/f.bin", 100, None, None);
        assert_eq!(resumed(decide_resume(&bare, &bare)), ResumeBasis::PathOnly);
        // LM on one side (no ETag) -> undecidable -> weak resume.
        assert_eq!(
            resumed(decide_resume(&stored, &facts("/f.bin", 100, None, None))),
            ResumeBasis::PathOnly
        );
    }

    /// Length mismatch: missing or unequal on either side -> from zero
    /// (ordered before the strong validators — length is the foundation
    /// of bitmap geometry).
    #[test]
    fn length_mismatch_restarts_even_with_matching_validator() {
        let stored = facts("/f.bin", 100, None, None);
        assert_eq!(
            restart(decide_resume(&stored, &facts("/f.bin", 101, None, None))),
            RestartReason::LengthMismatch
        );
        let no_len = ValidatorFacts {
            total_len: None,
            ..facts("/f.bin", 100, None, None)
        };
        assert_eq!(
            restart(decide_resume(&no_len, &facts("/f.bin", 100, None, None))),
            RestartReason::LengthMismatch
        );
    }

    /// query stripping: a signature URL's query drifts on every fetch; a
    /// matching path = the same resource (the weak-resume normal path);
    /// a changed path -> from zero.
    #[test]
    fn query_is_stripped_from_final_url() {
        let stored = facts("/f.bin", 100, None, None);
        // fresh carries the full URL (with query) — hits after
        // idempotent normalization.
        let fresh = facts("http://cdn.test/f.bin?sig=zzz&exp=1", 100, None, None);
        assert_eq!(
            resumed(decide_resume(&stored, &fresh)),
            ResumeBasis::PathOnly
        );
        // Query changes do not matter.
        let fresh2 = facts("/f.bin?sig=other", 100, None, None);
        assert_eq!(
            resumed(decide_resume(&stored, &fresh2)),
            ResumeBasis::PathOnly
        );
        // The path itself changed -> from zero.
        assert_eq!(
            restart(decide_resume(
                &stored,
                &facts("/other.bin", 100, None, None)
            )),
            RestartReason::PathMismatch
        );
        // Fragments are stripped too (the URL normalization defense
        // face).
        let frag = facts("/f.bin#frag", 100, None, None);
        assert_eq!(
            resumed(decide_resume(&stored, &frag)),
            ResumeBasis::PathOnly
        );
    }

    /// encoding not identity: either side -> from zero (the bitmap is
    /// not enabled); and ordered before length/validators (the
    /// no-bitmap shape has nothing to resume).
    #[test]
    fn encoding_not_identity_restarts() {
        let mut stored = facts("/f.bin", 100, Some("\"abc\""), None);
        stored.encoding_ok = false;
        let fresh = facts("/f.bin", 100, Some("\"abc\""), None);
        assert_eq!(
            restart(decide_resume(&stored, &fresh)),
            RestartReason::EncodingNotIdentity
        );
        assert_eq!(
            restart(decide_resume(&fresh, &stored)),
            RestartReason::EncodingNotIdentity
        );
    }

    /// url_path idempotent normalization face (full URL / path / empty
    /// path / authority only).
    #[test]
    fn url_path_normalization_matrix() {
        assert_eq!(url_path("http://h/f.bin?sig=x"), "/f.bin");
        assert_eq!(url_path("https://h/a/b/c"), "/a/b/c");
        assert_eq!(url_path("/f.bin?x=1"), "/f.bin");
        assert_eq!(url_path("/f.bin"), "/f.bin");
        assert_eq!(url_path("http://h"), "/");
        assert_eq!(url_path("http://h?q=1"), "/");
        assert_eq!(url_path("http://h/f#p?q=1"), "/f");
        // Idempotent: re-entering the normalization output used for
        // decisions does not drift.
        let once = url_path("http://h/f.bin?sig=x");
        assert_eq!(url_path(once), once);
    }

    /// strong_etag normalization face: trims whitespace / W/ and empty
    /// count as missing / strong tags preserved.
    #[test]
    fn strong_etag_normalization() {
        assert_eq!(strong_etag(Some(" \"abc\" ")), Some("\"abc\"".into()));
        assert_eq!(strong_etag(Some("W/\"abc\"")), None);
        assert_eq!(strong_etag(Some("")), None);
        assert_eq!(strong_etag(Some("   ")), None);
        assert_eq!(strong_etag(None), None);
        // Just the "W/" prefix itself (degenerate input) -> counted as
        // missing.
        assert_eq!(strong_etag(Some("W/")), None);
    }

    /// Digest face: canonical byte ordering is stable, the digest is
    /// 32 B, any field change drifts it; the digest / row payload
    /// `validator_digest` contract (the store only stores bytes); the
    /// version prefix makes the digest sensitive to format evolution
    /// (different prefixes never mismatch).
    #[test]
    fn validator_digest_is_stable_and_field_sensitive() {
        let a = facts("/f.bin", 100, Some("\"abc\""), None);
        let a2 = facts("/f.bin", 100, Some("\"abc\""), None);
        assert_eq!(
            ok(a.canonical_bytes(), "canonical 1"),
            ok(a2.canonical_bytes(), "canonical 2"),
            "the same payload orders its bytes identically"
        );
        // The version prefix is in place (the mismatch guard for format
        // evolution).
        assert!(
            a.canonical_bytes()
                .map(|b| b.starts_with(b"taiji/validator-facts/v1\n"))
                .unwrap_or(false),
            "canonical bytes must carry the format-version prefix"
        );
        let d1 = ok(validator_digest(&a), "digest 1");
        assert_eq!(d1.len(), 32);
        assert_eq!(d1, ok(validator_digest(&a2), "digest 2"));
        for mutated in [
            ValidatorFacts {
                total_len: Some(101),
                ..a.clone()
            },
            ValidatorFacts {
                etag: Some("\"x\"".into()),
                ..a.clone()
            },
            ValidatorFacts {
                final_url_path: "/g.bin".into(),
                ..a.clone()
            },
            ValidatorFacts {
                encoding_ok: false,
                ..a.clone()
            },
        ] {
            assert_ne!(
                ok(validator_digest(&mutated), "digest mutated"),
                d1,
                "a field change must drift the digest"
            );
        }
        // JSON payload round-trip (the restore read face's
        // deserialization path).
        let json = ok(serde_json::to_string(&a), "serialize");
        let back: ValidatorFacts = ok(serde_json::from_str(&json), "deserialize");
        assert_eq!(back, a);
    }
}

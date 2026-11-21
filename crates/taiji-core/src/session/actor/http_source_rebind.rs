//! Explicit source edits may change URL identity, never content identity.
use sha2::{Digest, Sha256};
use taiji_store::persist::HttpTaskRow;

use super::http_task::HttpPersistConfig;
use crate::session::http::{ValidatorFacts, strong_etag, validator_digest};

fn ledger_hash(uris: &[String]) -> String {
    let mut hash = Sha256::new();
    hash.update(b"taiji/http-source-rebind/v1\n");
    for uri in uris {
        hash.update((uri.len() as u64).to_be_bytes());
        hash.update(uri.as_bytes());
    }
    hash.finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub(super) fn authorize(row: &mut HttpTaskRow, uris: &[String]) {
    let mut cfg = HttpPersistConfig::from_json(&row.config_json);
    cfg.source_rebind = Some(ledger_hash(uris));
    row.config_json = cfg.to_json();
}

pub(super) fn validated(
    row: &HttpTaskRow,
    cfg: &HttpPersistConfig,
    uris: &[String],
    fresh: &ValidatorFacts,
) -> bool {
    if cfg.source_rebind.as_deref() != Some(ledger_hash(uris).as_str()) {
        return false;
    }
    matching_content(
        row.probe_json.as_deref(),
        row.validator_digest.as_deref(),
        fresh,
    )
}

fn matching_content(probe: Option<&str>, digest: Option<&[u8]>, fresh: &ValidatorFacts) -> bool {
    let Some(mut saved) = probe.and_then(|json| serde_json::from_str::<ValidatorFacts>(json).ok())
    else {
        return false;
    };
    // Require the same durable checkpoint and a content validator. A source
    // edit alone cannot authorize unknown content or a corrupted checkpoint.
    if validator_digest(&saved).ok().as_deref() != digest
        || fresh.total_len.is_none()
        || !fresh.encoding_ok
        || (strong_etag(fresh.etag.as_deref()).is_none()
            && fresh.last_modified.as_deref().is_none_or(str::is_empty))
    {
        return false;
    }
    saved.final_url_path.clone_from(&fresh.final_url_path);
    saved == *fresh
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rebind_accepts_changed_path_but_requires_the_same_validated_content() {
        let saved = ValidatorFacts {
            final_url_path: "/old".into(),
            total_len: Some(1024),
            etag: Some("\"content\"".into()),
            last_modified: None,
            encoding_ok: true,
        };
        let json = serde_json::to_string(&saved).unwrap_or_else(|e| panic!("fixture: {e}"));
        let digest = validator_digest(&saved).unwrap_or_else(|e| panic!("fixture: {e}"));
        let mut fresh = saved.clone();
        fresh.final_url_path = "/new".into();
        assert!(matching_content(Some(&json), Some(&digest), &fresh));
        fresh.etag = Some("\"changed\"".into());
        assert!(!matching_content(Some(&json), Some(&digest), &fresh));
        fresh = saved.clone();
        fresh.total_len = Some(2048);
        assert!(!matching_content(Some(&json), Some(&digest), &fresh));
        fresh = saved.clone();
        fresh.encoding_ok = false;
        assert!(!matching_content(Some(&json), Some(&digest), &fresh));
        assert!(!matching_content(Some(&json), Some(&[0]), &saved));
        assert!(!matching_content(None, Some(&digest), &saved));
        let unknown = ValidatorFacts {
            etag: None,
            ..saved
        };
        let json = serde_json::to_string(&unknown).unwrap_or_else(|e| panic!("fixture: {e}"));
        let digest = validator_digest(&unknown).unwrap_or_else(|e| panic!("fixture: {e}"));
        assert!(!matching_content(Some(&json), Some(&digest), &unknown));
    }

    #[test]
    fn ledger_hash_preserves_order_duplicates_and_boundaries() {
        assert_ne!(
            ledger_hash(&["ab".into(), "c".into()]),
            ledger_hash(&["a".into(), "bc".into()])
        );
        assert_ne!(
            ledger_hash(&["a".into(), "b".into()]),
            ledger_hash(&["b".into(), "a".into()])
        );
        assert_ne!(
            ledger_hash(&["a".into()]),
            ledger_hash(&["a".into(), "a".into()])
        );
    }
}

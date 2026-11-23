//! Parse and apply the head/tail preference without changing explicit policies.
use super::SessionError;
use super::options::{TaskOptionPatch, parse_size};
use crate::engine::SchedulerPolicy;
use std::collections::BTreeMap;
use taiji_engine::preview::PreviewPieces;

/// aria2 bt-prioritize-piece grammar: head[=SIZE],tail[=SIZE], 1 MiB default.
/// Repeated regions form a union (the largest size wins); blank disables it.
pub fn parse_preview_pieces(value: &str) -> Result<PreviewPieces, String> {
    let mut preview = PreviewPieces::default();
    for part in value
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
    {
        let (name, size) = part.split_once('=').unwrap_or((part, "1M"));
        let bytes = parse_size(size)
            .ok_or_else(|| "taiji.option.invalid: invalid bt-prioritize-piece size".to_owned())?;
        match name {
            "head" => preview.head = preview.head.max(bytes),
            "tail" => preview.tail = preview.tail.max(bytes),
            _ => {
                return Err(
                    "taiji.option.invalid: bt-prioritize-piece expects head or tail".into(),
                );
            }
        }
    }
    Ok(preview)
}

pub(crate) fn validate(options: &BTreeMap<String, String>) -> Result<(), SessionError> {
    if let Some(value) = options.get("bt-prioritize-piece") {
        parse_preview_pieces(value).map_err(SessionError::failed)?;
    }
    Ok(())
}

pub(crate) fn apply(policy: &mut SchedulerPolicy, patch: &TaskOptionPatch) {
    if let Some(sequential) = patch.bt_sequential_download {
        *policy = if sequential {
            SchedulerPolicy::sequential()
        } else {
            SchedulerPolicy::default()
        };
    }
    if let SchedulerPolicy::RarestFirst(params) = policy
        && let Some(preview) = patch.preview_pieces
    {
        params.preview = (!preview.is_empty()).then_some(preview);
    }
}

pub(crate) fn initial(patch: &TaskOptionPatch) -> SchedulerPolicy {
    let mut policy = SchedulerPolicy::default();
    apply(&mut policy, patch);
    policy
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preview_option_matches_head_tail_size_and_union_semantics() {
        for (text, head, tail) in [
            ("", 0, 0),
            ("head", 1048576, 0),
            ("tail", 0, 1048576),
            ("head=10M,tail=10M", 10485760, 10485760),
            ("head=3,head=2,tail=1", 3, 1),
            ("head=0,tail=0", 0, 0),
        ] {
            let preview =
                parse_preview_pieces(text).unwrap_or_else(|e| panic!("valid option: {e}"));
            assert_eq!(preview, PreviewPieces { head, tail });
            assert_eq!(parse_preview_pieces(&preview.option_value()), Ok(preview));
        }
        for text in [
            "middle=4",
            "head=-1",
            "head=",
            "head=18446744073709551616",
            "head=18446744073709551615G",
        ] {
            assert!(parse_preview_pieces(text).is_err(), "{text}");
        }
    }
    #[test]
    fn preview_preserves_explicit_strategy_and_roundtrips_default_configs() {
        let patch = super::super::options::parse_task_options(&BTreeMap::from([(
            "bt-prioritize-piece".into(),
            "head=10M,tail=10M".into(),
        )]));
        let policy = initial(&patch);
        assert_eq!(
            serde_json::from_str::<SchedulerPolicy>(
                &serde_json::to_string(&policy).unwrap_or_else(|e| panic!("serialize: {e}"))
            )
            .unwrap_or_else(|e| panic!("deserialize: {e}")),
            policy
        );
        let mut sequential = SchedulerPolicy::sequential();
        apply(&mut sequential, &patch);
        assert_eq!(sequential, SchedulerPolicy::sequential());
        let old: SchedulerPolicy = serde_json::from_str(r#"{"policy":"rarest_first","params":{}}"#)
            .unwrap_or_else(|e| panic!("old default: {e}"));
        assert_eq!(old, SchedulerPolicy::default());
        assert_eq!(
            serde_json::to_string(&old).unwrap_or_else(|e| panic!("serialize: {e}")),
            r#"{"policy":"rarest_first","params":{}}"#
        );
    }
}

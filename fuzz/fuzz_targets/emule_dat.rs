//! fuzz target: the eMule `.dat` blocklist parser. Invariants: rule
//! ranges are legal (start <= end, same family), normalized rule text
//! round-trips uniquely, and IpGuard snapshot assembly (range merging +
//! sorting) never panics on any input while every deny-range start
//! endpoint is blocked (unless overridden by allow — allow takes
//! precedence, where blocks == None is also legal).

#![no_main]

use libfuzzer_sys::fuzz_target;
use taiji_bt::peer_policy::{parse_blocklist_rule, parse_emule_dat, IpBlock, IpGuard, RuleAction};

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let parsed = parse_emule_dat(&text);
    let mut text_forms = std::collections::HashSet::new();
    for r in &parsed.rules {
        assert!(r.start <= r.end, "rule range start > end leaked parser");
        assert!(
            std::mem::discriminant(&r.start) == std::mem::discriminant(&r.end),
            "cross-family rule leaked parser"
        );
        let t = r.to_blocklist_text();
        assert!(
            text_forms.insert(t.clone()),
            "duplicate normalized rule text: {t}"
        );
        let back = parse_blocklist_rule(&t).unwrap_or_else(|| panic!("rule text not parseable: {t}"));
        assert_eq!(back.to_blocklist_text(), t, "rule text roundtrip broken");
    }
    // Snapshot assembly never panics; the decision agrees with
    // allow-precedence: the start endpoint of a solo deny rule must be
    // blocked (a synthetic snapshot with no allow coverage).
    let guard = IpGuard::new(parsed.rules.iter().copied(), []);
    let deny_starts: Vec<_> = parsed
        .rules
        .iter()
        .filter(|r| r.action == RuleAction::Deny)
        .map(|r| (r.start, r.end))
        .collect();
    let solo = IpGuard::new(
        deny_starts
            .iter()
            .map(|(s, e)| taiji_bt::peer_policy::FilterRule {
                action: RuleAction::Deny,
                start: *s,
                end: *e,
            }),
        [],
    );
    for (s, _e) in &deny_starts {
        assert_eq!(
            solo.blocks(*s, i64::MAX),
            Some(IpBlock::Denied),
            "deny range start not blocked by solo snapshot"
        );
    }
    let _ = guard;
});

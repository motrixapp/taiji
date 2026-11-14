//! Option-name tables and gates — the adapter layer's option face.
//!
//! Three pieces, shallow by design (Phase C's cut line):
//!
//! - the metalink seam name tables (rpc-owned names, moved from
//!   `crate::metalink`);
//!
//! - [`classify`], the name-classification gate over the core
//!   declaration tables (the single source of "which names exist");
//!   every rpc-side option-name touchpoint (metalink seam rejection,
//!   addUri-family option intake, change*) passes through it —
//!   observationally (warn + count), never rejecting: the v1 wire
//!   contract ignores unknown names exactly like the reference;
//!
//! - [`serialize_options`], the echo serialization gate: every
//!   getOption/getGlobalOption response body is rendered through it,
//!   and every key must classify as known — an unknown echo key is a
//!   table/echo drift and surfaces as a warn + counter (never dropped:
//!   the wire bytes stay identical).
//!
//! Explicitly **not** migrated here: the behavior tables
//! (`GLOBAL_PATCH_TABLE` & co) and the actor special arms (bt-tracker
//! hot import, Motrix keys, HTTP defaults collection) — moving them
//! requires the SessionCommand typed-patch rework (plan step C4);
//! their names stay single-sourced in core `session::options`.
//!
//! Upstream anchor mapping: docs/design/rpc.md

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::Value;
use tracing::warn;

use taiji_core::session::{ARIA2_OPTION_NAMES, DECLARED_OPTION_DIFFS};

/// The legacy aria2 metalink option family (the metalink group:
/// unsupported, ignored with a warning; listed in the declared
/// differences). Moved from `crate::metalink` — the seam names are
/// rpc-owned (aria2 1.37.0 `prefs.cc` has no such names).
#[cfg(feature = "metalink")]
pub(crate) const UNSUPPORTED_METALINK_OPTIONS: &[&str] = &[
    "metalink-enable-unique-protocol",
    "metalink-force-protocol",
    "metalink-language",
    "metalink-location",
    "metalink-os",
    "metalink-preferred-protocol",
    "metalink-version",
];

/// The HTTP header auto-discovery option (default off; metalink group).
/// true is accepted but treated as invalid with a warning —
/// content-sniffing auto-conversion is not in this build (module-doc
/// declared difference).
#[cfg(feature = "metalink")]
pub(crate) const AUTO_DISCOVER_OPTION: &str = "metalink-enable-auto-discover";

/// Option-name class (the classification gate's product).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OptionClass {
    /// An aria2 reference-table name (`ARIA2_OPTION_NAMES`).
    Aria2Name,
    /// A declared taiji extension/renamed name (`DECLARED_OPTION_DIFFS`
    /// — the acceptance whitelist entries the reference has no such
    /// name for).
    TaijiExtension,
    /// Not on any declaration table — the reference's
    /// "unacceptable options ignored" rule applies.
    Unknown,
}

/// Classify an option name against the core declaration tables (the
/// single source; the same data core's `option_name_declared` reads).
/// This
/// is a *gate*, not a validator: callers warn + count on Unknown, they
/// never reject — the v1 wire contract ignores unknown names exactly
/// like the reference (RpcMethod.cc gatherOption).
pub(crate) fn classify(name: &str) -> OptionClass {
    if ARIA2_OPTION_NAMES.contains(&name) {
        OptionClass::Aria2Name
    } else if DECLARED_OPTION_DIFFS.iter().any(|(n, _)| *n == name) {
        OptionClass::TaijiExtension
    } else {
        OptionClass::Unknown
    }
}

/// Unknown-name observations at the option intake touchpoints (warn +
/// count; the counter is read by tests and the operator face — never a
/// rejection, see [`classify`]).
static UNKNOWN_OPTION_KEYS: AtomicU64 = AtomicU64::new(0);

/// The option-intake gate: every name handed to the session through an
/// add*/change* method is classified here; Unknown names warn + count
/// (the reference's ignore rule keeps the wire behavior identical).
pub(crate) fn note_option_intake(options: &BTreeMap<String, String>, face: &str) {
    for name in options.keys() {
        if classify(name) == OptionClass::Unknown {
            UNKNOWN_OPTION_KEYS.fetch_add(1, Ordering::Relaxed);
            warn!(
                target: "taiji::rpc::aria2::option",
                option = %name,
                face,
                "option name is not on any declaration table; ignored (the reference rule)"
            );
        }
    }
}

/// The echo serialization gate: getOption/getGlobalOption response
/// bodies render through this function. Every key must classify as
/// known (an unknown echo key = table/echo drift: warn + count, never
/// dropped — the wire bytes stay identical).
pub(crate) fn serialize_options(map: &BTreeMap<String, String>) -> Value {
    for name in map.keys() {
        if classify(name) == OptionClass::Unknown {
            UNKNOWN_OPTION_KEYS.fetch_add(1, Ordering::Relaxed);
            warn!(
                target: "taiji::rpc::aria2::option",
                option = %name,
                "echo key is not on any declaration table (table/echo drift)"
            );
        }
    }
    serde_json::to_value(map).unwrap_or(Value::Null)
}

#[cfg(test)]
mod tests {
    use super::*;
    use taiji_core::session::{GlobalOptions, global_option_echo, option_name_declared};

    /// The echo key set ≡ the classification-known set, member for
    /// member: every key of the default global echo (the same face the
    /// live differential audits) must classify as known — mirroring
    /// core's `global_option_echo_keys_are_fully_declared` /
    /// `motrix_sent_rpc_options_are_fully_classified` caliber (the
    /// accepted-name tables stay core-side single sources; the mirror
    /// here pins the rpc gate itself).
    #[test]
    fn global_echo_keys_all_classify_known() {
        let echo = global_option_echo(&GlobalOptions::default());
        assert!(!echo.is_empty(), "the echo face must be non-empty");
        let mut unknown: Vec<&str> = echo
            .keys()
            .map(String::as_str)
            .filter(|k| classify(k) == OptionClass::Unknown)
            .collect();
        unknown.sort_unstable();
        assert!(
            unknown.is_empty(),
            "echo keys off every declaration table: {unknown:?}"
        );
    }

    /// serialize_options is byte-identical to the raw map rendering
    /// (the gate observes, it never rewrites the wire).
    #[test]
    fn serialize_options_keeps_wire_bytes() {
        let mut map = BTreeMap::new();
        map.insert("dir".to_string(), "/tmp".to_string());
        map.insert("bt-tracker".to_string(), "http://t/a".to_string());
        assert_eq!(
            serialize_options(&map),
            serde_json::to_value(&map).unwrap_or_default()
        );
    }

    /// Classification partition sanity on representative names: the
    /// reference face, the declared-extension face, and the off-table
    /// face (the reference's ignore rule).
    #[cfg(feature = "metalink")]
    #[test]
    fn classify_partitions_reference_extension_unknown() {
        assert_eq!(classify("dir"), OptionClass::Aria2Name);
        assert_eq!(classify("bt-tracker"), OptionClass::Aria2Name);
        // The seam's legacy family are reference names (prefs.cc);
        // the two seam names the reference has no such name for are
        // declared differences.
        assert_eq!(classify("metalink-language"), OptionClass::Aria2Name);
        assert_eq!(classify(AUTO_DISCOVER_OPTION), OptionClass::TaijiExtension);
        assert_eq!(classify("bt-tracker-file"), OptionClass::TaijiExtension);
        assert_eq!(classify("totally-unknown-key"), OptionClass::Unknown);
        assert!(!option_name_declared("totally-unknown-key"));
    }

    /// The metalink seam's non-reference names stay on the
    /// declared-difference face (aria2 1.37.0 prefs.cc has no such
    /// names — they must never sneak into the reference list).
    #[cfg(feature = "metalink")]
    #[test]
    fn metalink_seam_names_stay_on_the_difference_face() {
        for name in [AUTO_DISCOVER_OPTION, "metalink-force-protocol"] {
            assert!(
                DECLARED_OPTION_DIFFS.iter().any(|(n, _)| *n == name),
                "{name} must stay a declared difference entry"
            );
            assert!(
                !ARIA2_OPTION_NAMES.contains(&name),
                "{name} is not a reference name"
            );
        }
        // The seam table itself stays sorted and duplicate-free (the
        // accepted set is mirrored core-side by
        // METALINK_ACCEPTED_SEAM_OPTION_NAMES).
        let names = UNSUPPORTED_METALINK_OPTIONS;
        assert!(
            names.windows(2).all(|w| w[0] < w[1]),
            "the seam table must be sorted and duplicate-free"
        );
    }
}

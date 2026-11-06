//! fuzz target: IGD device-description / SOAP response XML parsing.
//!
//! Contract: `parse_device_description_for_fuzz` /
//! `parse_action_response_for_fuzz` are total over any byte string
//! (Ok/Err, never panic or UB) — deeply nested input is rejected by the
//! [`MAX_XML_DEPTH`] byte-level pre-check (roxmltree 0.20 parse aborts on
//! deeply nested documents through recursion, see the igd.rs pre-check
//! notes) and garbage bytes fall to roxmltree error classification. The
//! same implementation serves production (the innermost parsing surface
//! after the bounded transfer), preventing behavior drift.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Surface 1: device-description scan (depth pre-check → roxmltree →
    // explicit stack walk).
    let _ = taiji_io::nat::igd::parse_device_description_for_fuzz(data);
    // Surface 2: SOAP action response parsing (Body location → Fault →
    // parameter collection; the response side of the same parsing stack,
    // any action name — parsing does not depend on a specific action).
    let _ = taiji_io::nat::igd::parse_action_response_for_fuzz("AddPortMapping", data);
});

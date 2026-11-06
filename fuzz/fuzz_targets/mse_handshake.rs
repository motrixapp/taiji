#![no_main]

//! fuzz target: MSE handshake stream parsing.
//!
//! Invariants: on any byte sequence the bidirectional handshake pure state
//! machines ([`ReceiverParser`]/[`InitiatorParser`]) and the sniff pure
//! function are total, never panic, never loop forever; fatal inputs may
//! only fail as `MseError` (the caller disconnects).
//!
//! Key material is derived from the fuzz input (fixed private key /
//! directional keys injected), making the parse paths fully input-driven
//! and reproducible.

use taiji_io::mse::{
    identify, InitiatorParser, ReceiverParser, KEY_LENGTH,
};
use libfuzzer_sys::fuzz_target;

const IH_A: [u8; 20] = [0xAA; 20];
const IH_B: [u8; 20] = [0xBB; 20];

/// Derive the 96B secret deterministically from the fuzz input
/// (reproducible, covers the full byte domain).
fn derive_secret(data: &[u8]) -> [u8; KEY_LENGTH] {
    let mut s = [0u8; KEY_LENGTH];
    for (i, b) in s.iter_mut().enumerate() {
        *b = data.get(i % data.len().max(1)).copied().unwrap_or(i as u8);
    }
    s
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    // 1) The sniff pure function: arbitrary input.
    let _ = identify(data, b"BitTorrent protocol");

    let secret = derive_secret(data);
    let body = &data[1..];

    // 2) Receiver state machine: multiple candidates + arbitrary chunking.
    let mut rx = ReceiverParser::new(vec![IH_A, IH_B], secret);
    for chunk in data.chunks(1 + (data.len() % 7)) {
        if rx.push(chunk).unwrap_or(true) {
            break;
        }
    }
    let _ = rx.is_done();
    let _ = rx.outcome();
    let (_outcome, _decryptor, _leftover) = rx.finish();

    // 3) Initiator state machine: directional key + marker search +
    // select/padD.
    let (_, peer_key) =
        taiji_io::mse::cipher_keys(&secret, &IH_A, taiji_io::mse::Direction::Initiator);
    let mut ix = InitiatorParser::new(peer_key);
    for chunk in body.chunks(1 + (body.len() % 5)) {
        if ix.push(chunk).unwrap_or(true) {
            break;
        }
    }
    let (_select, _d, _leftover) = ix.finish();
});

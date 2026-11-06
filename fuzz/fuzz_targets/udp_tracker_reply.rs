#![no_main]

//! fuzz target: UDP tracker reply parsing.
//!
//! Invariant: feeding any byte sequence to
//! `UdpTrackerClient::receive_reply` as a reply never panics or hangs —
//! the action dispatch (CONNECT exactly 16B / ANNOUNCE >= 20B with 6B peer
//! steps / SCRAPE 12B per hash / ERROR >= 8B / unknown action), the length
//! guards, and the unknown-transaction ignore path are all covered. To
//! make every dispatch branch reachable, a deterministic driver sets up an
//! in-flight CONNECT→ANNOUNCE→SCRAPE transaction chain and rewrites the
//! input's transaction_id slot (data[4..8]) to an in-flight transaction id
//! (the payload bytes stay arbitrary).

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use taiji_bt::tracker::udp::{UdpReply, UdpRequest, UdpTrackerClient};
use libfuzzer_sys::fuzz_target;
use rand::SeedableRng as _;

fuzz_target!(|data: &[u8]| {
    let tracker: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1337));
    let mut rng = rand::rngs::StdRng::from_seed([0x5a; 32]);
    let mut client = UdpTrackerClient::new();
    let base = std::time::Instant::now();

    // Enqueue one announce + one scrape transaction (both dispatch targets
    // of BEP15 replies).
    client.add_request(UdpRequest::announce(tracker, [7; 20], 1));
    client.add_request(UdpRequest::scrape(tracker, vec![[1; 20], [2; 20]]));

    // Build the in-flight chain: CONNECT → (reply) → ANNOUNCE → SCRAPE,
    // transaction ids read back from the real outgoing frames.
    let Some((_, connect_frame)) = client.create_request(&mut rng, base) else {
        return;
    };
    client.request_sent(base);
    let mut reply = Vec::new();
    reply.extend_from_slice(&0i32.to_be_bytes());
    reply.extend_from_slice(
        &u32::from_be_bytes([
            connect_frame[12],
            connect_frame[13],
            connect_frame[14],
            connect_frame[15],
        ])
        .to_be_bytes(),
    );
    reply.extend_from_slice(&0xdead_c0de_dead_c0deu64.to_be_bytes());
    let _ = client.receive_reply(tracker, &reply, base);

    let tids: Vec<u32> = (0..2)
        .filter_map(|_| match client.create_request(&mut rng, base) {
            Some((_, frame)) => {
                client.request_sent(base);
                Some(u32::from_be_bytes([frame[12], frame[13], frame[14], frame[15]]))
            }
            None => None,
        })
        .collect();
    if tids.len() < 2 {
        return;
    }

    // Feed the arbitrary payload once per announce and scrape transaction
    // (tid slot rewritten).
    for tid in tids {
        let mut packet = data.to_vec();
        if packet.len() < 8 {
            packet.resize(8, 0);
        }
        packet[4..8].copy_from_slice(&tid.to_be_bytes());
        match client.receive_reply(tracker, &packet, base) {
            Ok(Some(UdpReply::Announce(req))) => {
                let _ = req.announce_reply().map(|r| r.peers.len());
            }
            Ok(Some(UdpReply::Scrape(req))) => {
                let _ = req.scrape_reply().map(|e| e.len());
            }
            Ok(_) => {}
            Err(_) => {}
        }
    }
});

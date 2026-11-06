//! criterion micro-benchmark: peer frame codec.
//!
//! Frame-layer pure-function segments — `Message::encode` /
//! `Message::decode_body` / `FrameCodec` (the tokio_util Decoder half).
//! Hot shapes = piece frames (16KiB blocks, the main data-plane payload) +
//! bitfield (a v2-synthetic bitmap size) + extended (a BEP-10 dict).
//! Deterministic inputs, no IO/clock.
//!
//! Run: `cargo bench -p taiji-bt --bench bench_peer_frame` (release).

use std::hint::black_box;

use bytes::{Buf, Bytes, BytesMut};
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use tokio_util::codec::Decoder;

use taiji_bt::peer_wire::{FrameCodec, Message};

/// Deterministic 16KiB block (fixed-seed XorShift; hash-irrelevant, just
/// fills the payload).
fn deterministic_block(len: usize, seed: u64) -> Bytes {
    let mut x = seed;
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        let v = x.to_le_bytes();
        let n = (len - out.len()).min(8);
        out.extend_from_slice(&v[..n]);
    }
    Bytes::from(out)
}

fn bench_peer_frame(c: &mut Criterion) {
    let block = deterministic_block(16 * 1024, 0x0BAD_C0DE_2026_0831);
    // v2 synthetic bitmap size (SPEC §4.4): 2048 pieces -> 256B bitmap.
    let bitfield = deterministic_block(256, 0x1B17_F1E1_D000_2048);
    let ext_payload = deterministic_block(64, 0x00E7_ED10_A1CE);

    let piece_frame = Message::Piece {
        index: 7,
        begin: 3 * 16 * 1024,
        block: block.clone(),
    };
    let bitfield_frame = Message::Bitfield {
        bits: bitfield.clone(),
    };
    let ext_frame = Message::Extended {
        ext_id: 1,
        payload: ext_payload.clone(),
    };
    let piece_bytes = piece_frame.encode();
    let bitfield_bytes = bitfield_frame.encode();

    let mut group = c.benchmark_group("peer_frame");
    group.throughput(Throughput::Bytes(piece_bytes.len() as u64));

    group.bench_function("encode/piece_16kib", |b| {
        b.iter(|| black_box(&piece_frame).encode())
    });
    group.bench_function("encode/bitfield_2048pieces", |b| {
        b.iter(|| black_box(&bitfield_frame).encode())
    });
    group.bench_function("encode/extended_bep10", |b| {
        b.iter(|| black_box(&ext_frame).encode())
    });

    group.bench_function("decode_body/piece_16kib", |b| {
        b.iter(
            || match Message::decode_body(black_box(&piece_bytes[4..])) {
                Ok(m) => m,
                Err(e) => panic!("piece frame decode failed: {e:?}"),
            },
        )
    });
    group.bench_function("decode_body/bitfield_2048pieces", |b| {
        b.iter(
            || match Message::decode_body(black_box(&bitfield_bytes[4..])) {
                Ok(m) => m,
                Err(e) => panic!("bitfield frame decode failed: {e:?}"),
            },
        )
    });

    // The FrameCodec half (connection-layer decode path): a stream of 4
    // consecutive piece frames.
    let mut stream = BytesMut::new();
    for i in 0u32..4 {
        stream.extend_from_slice(&piece_bytes);
        let _ = i;
    }
    group.throughput(Throughput::Bytes(stream.len() as u64));
    group.bench_function("frame_codec/4x_piece_16kib_stream", |b| {
        b.iter_batched(
            || stream.clone(),
            |mut src| {
                let mut codec = FrameCodec::default();
                let mut count = 0u32;
                while src.has_remaining() {
                    match codec.decode(&mut src) {
                        Ok(Some(_)) => count += 1,
                        Ok(None) => break,
                        Err(e) => panic!("frame codec error: {e:?}"),
                    }
                }
                black_box(count)
            },
            criterion::BatchSize::SmallInput,
        )
    });
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default();
    targets = bench_peer_frame
}
criterion_main!(benches);

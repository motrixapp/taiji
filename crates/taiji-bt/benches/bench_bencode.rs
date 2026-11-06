//! criterion micro-benchmark: bencode codec.
//!
//! Hot-path pure-function segments; all inputs are deterministically
//! constructed — the hybrid fixture (`tests/fixtures/hybrid_16k.torrent`,
//! a real BEP-52 layout) plus programmatically generated metadata shapes
//! (fixed file-tree depth/file counts). No network, no clock, no runtime
//! randomness (fixed-seed XorShift); reproducible.
//!
//! Run: `cargo bench -p taiji-bt --bench bench_bencode` (release).

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};

use taiji_bt::bencode::{Value, decode, decode_permissive, decode_with_info_span, encode};

/// In-bench decode helper (no expect/unwrap — workspace lint; same style
/// as unit tests).
fn dec(input: &[u8]) -> Value {
    match decode(input) {
        Ok(v) => v,
        Err(e) => panic!("decode({input:?}) unexpectedly failed: {e:?}"),
    }
}

fn dec_span(input: &[u8]) -> std::ops::Range<usize> {
    match decode_with_info_span(input) {
        Ok((_, span)) => span,
        Err(e) => panic!("decode_with_info_span({input:?}) failed: {e:?}"),
    }
}

fn enc(value: &Value) -> Vec<u8> {
    match encode(value) {
        Ok(b) => b,
        Err(e) => panic!("encode unexpectedly failed: {e:?}"),
    }
}

/// Fixed-seed XorShift64 (deterministic dict keys etc.; no runtime
/// randomness).
struct XorShift(u64);

impl XorShift {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn fill(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(8) {
            let v = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&v[..chunk.len()]);
        }
    }
}

/// Programmatic metadata shape: a v2 file tree dict with `n_files` files
/// (keys all ascending — the canonical constraint). Returns encoded
/// bytes.
fn synthetic_metadata(n_files: usize) -> Vec<u8> {
    let mut rng = XorShift(0x5EED_4815_1623_42A7);
    let mut pieces_root = [0u8; 32];
    rng.fill(&mut pieces_root);
    // file tree: leaves inserted in name byte order (name = fixed prefix
    // + big-endian index, ascending).
    let mut leaves: Vec<(Vec<u8>, Value)> = Vec::new();
    for i in 0..n_files {
        let mut name = b"f".to_vec();
        name.extend_from_slice(format!("{i:08}.bin").as_bytes());
        let attr = Value::Dict(vec![
            (b"length".to_vec(), Value::Int(16384 * (i as i64 % 7 + 1))),
            (b"pieces root".to_vec(), Value::Bytes(pieces_root.to_vec())),
        ]);
        leaves.push((name, attr));
    }
    let info = Value::Dict(vec![
        (b"file tree".to_vec(), Value::Dict(leaves)),
        (b"meta version".to_vec(), Value::Int(2)),
        (b"name".to_vec(), Value::Bytes(b"bench-payload".to_vec())),
        (b"piece length".to_vec(), Value::Int(16 * 1024)),
    ]);
    let top = Value::Dict(vec![
        (
            b"announce".to_vec(),
            Value::Bytes(b"http://bench.invalid/an".to_vec()),
        ),
        (b"info".to_vec(), info),
    ]);
    enc(&top)
}

/// Multi-file v1 shape (a long `pieces` string — the large-string decode
/// path).
fn synthetic_v1_pieces(n_pieces: usize) -> Vec<u8> {
    let mut rng = XorShift(0xBADC_0FEE_0DDB_A115);
    let mut pieces = vec![0u8; 20 * n_pieces];
    rng.fill(&mut pieces);
    let info = Value::Dict(vec![
        (b"length".to_vec(), Value::Int(16 * 1024 * n_pieces as i64)),
        (b"name".to_vec(), Value::Bytes(b"bench-v1".to_vec())),
        (b"piece length".to_vec(), Value::Int(16 * 1024)),
        (b"pieces".to_vec(), Value::Bytes(pieces)),
    ]);
    let top = Value::Dict(vec![
        (
            b"announce".to_vec(),
            Value::Bytes(b"http://bench.invalid/an".to_vec()),
        ),
        (b"info".to_vec(), info),
    ]);
    enc(&top)
}

fn bench_bencode(c: &mut Criterion) {
    let hybrid = include_bytes!("../tests/fixtures/hybrid_16k.torrent");
    let meta64 = synthetic_metadata(64);
    let meta1024 = synthetic_metadata(1024);
    let v1_2k = synthetic_v1_pieces(2048);

    let mut group = c.benchmark_group("bencode");
    group.throughput(criterion::Throughput::Bytes(hybrid.len() as u64));
    group.bench_function("decode/hybrid_fixture_16k", |b| {
        b.iter(|| dec(black_box(hybrid)))
    });
    group.bench_function("decode_with_info_span/hybrid_fixture_16k", |b| {
        b.iter(|| dec_span(black_box(hybrid)))
    });
    group.throughput(criterion::Throughput::Bytes(meta64.len() as u64));
    group.bench_function("decode/synthetic_metadata_64files", |b| {
        b.iter(|| dec(black_box(&meta64)))
    });
    group.throughput(criterion::Throughput::Bytes(meta1024.len() as u64));
    group.bench_function("decode/synthetic_metadata_1024files", |b| {
        b.iter(|| dec(black_box(&meta1024)))
    });
    group.throughput(criterion::Throughput::Bytes(v1_2k.len() as u64));
    group.bench_function("decode/synthetic_v1_2048pieces", |b| {
        b.iter(|| dec(black_box(&v1_2k)))
    });
    group.bench_function("encode/roundtrip_v1_2048pieces", |b| {
        let value = dec(&v1_2k);
        b.iter(|| enc(black_box(&value)))
    });
    // permissive path (peer message face: BEP-10/PEX dicts need not be
    // ordered).
    group.throughput(criterion::Throughput::Bytes(v1_2k.len() as u64));
    group.bench_function("decode_permissive/synthetic_v1_2048pieces", |b| {
        b.iter(|| match decode_permissive(black_box(&v1_2k)) {
            Ok(v) => v,
            Err(e) => panic!("decode_permissive failed: {e:?}"),
        })
    });
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default();
    targets = bench_bencode
}
criterion_main!(benches);

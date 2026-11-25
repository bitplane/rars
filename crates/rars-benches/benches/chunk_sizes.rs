use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rars::codec::rar29::{
    unpack29_encode_literals, EncodeOptions as Rar29EncodeOptions, Unpack29, Unpack29Encoder,
};
use rars::codec::rar50::{
    DecodeMode, EncodeOptions as Rar50EncodeOptions, Unpack50Decoder, Unpack50Encoder,
};
use std::{cell::OnceCell, hint::black_box};

const CHUNK_SIZES: &[usize] = &[1024, 4 * 1024, 16 * 1024, 64 * 1024, 256 * 1024];

fn payload(size: usize) -> Vec<u8> {
    const PHRASE: &[u8] = b"rars benchmark payload with repeated text and changing literals\n";

    let mut out = Vec::with_capacity(size);
    let mut state = 0x9e37_79b9_u32;
    while out.len() < size {
        out.extend_from_slice(PHRASE);
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        out.push((state >> 24) as u8);
        out.push((out.len() & 0xff) as u8);
    }
    out.truncate(size);
    out
}

fn chunk_label(bytes: usize) -> String {
    if bytes >= 1024 {
        format!("{}KiB", bytes / 1024)
    } else {
        format!("{bytes}B")
    }
}

fn rar29_encoder() -> Unpack29Encoder {
    let options = Rar29EncodeOptions::new(64);
    Unpack29Encoder::with_options(options)
}

fn rar50_encoder() -> Unpack50Encoder {
    let options = Rar50EncodeOptions::new(64);
    Unpack50Encoder::with_options(options)
}

fn encode_rar29(input: &[u8]) -> Vec<u8> {
    rar29_encoder()
        .encode_member(input)
        .expect("RAR 2.9 compression should succeed")
}

fn decode_rar29(input: &[u8], output_size: usize) -> Vec<u8> {
    Unpack29::new()
        .decode_non_solid_member(input, output_size)
        .expect("RAR 2.9 decompression should succeed")
}

fn encode_rar50(input: &[u8]) -> Vec<u8> {
    rar50_encoder()
        .encode_member(input, 0)
        .expect("RAR 5.0 compression should succeed")
}

fn decode_rar50(input: &[u8], output_size: usize) -> Vec<u8> {
    Unpack50Decoder::new()
        .decode_member(input, 0, output_size, false, DecodeMode::Lz)
        .expect("RAR 5.0 decompression should succeed")
}

// Checked when the case first runs rather than while the groups are set up,
// so a filtered run of another case skips the extra encode and decode.
fn check_optimal_round_trip(options: Rar50EncodeOptions, data: &[u8]) {
    let packed = Unpack50Encoder::with_options(options)
        .encode_member(data, 0)
        .unwrap();
    assert_eq!(decode_rar50(&packed, data.len()), data);
}

fn bench_compression(c: &mut Criterion) {
    let mut group = c.benchmark_group("compression_by_chunk_size");

    for &size in CHUNK_SIZES {
        let data = payload(size);
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(
            BenchmarkId::new("rar29_lz", chunk_label(size)),
            &data,
            |b, data| {
                b.iter(|| black_box(encode_rar29(black_box(data))));
            },
        );

        group.bench_with_input(
            BenchmarkId::new("rar50_lz", chunk_label(size)),
            &data,
            |b, data| {
                b.iter(|| black_box(encode_rar50(black_box(data))));
            },
        );
    }

    group.finish();
}

fn bench_decompression(c: &mut Criterion) {
    let mut group = c.benchmark_group("decompression_by_chunk_size");

    for &size in CHUNK_SIZES {
        let data = payload(size);
        group.throughput(Throughput::Bytes(size as u64));

        // Packed and round-trip checked when the case first runs, so a
        // filtered run of another case (nextest runs each in its own process)
        // skips the encoding.
        let rar29_packed = OnceCell::new();
        group.bench_function(BenchmarkId::new("rar29_lz", chunk_label(size)), |b| {
            let packed = rar29_packed.get_or_init(|| {
                let packed = encode_rar29(&data);
                assert_eq!(decode_rar29(&packed, data.len()), data);
                packed
            });
            b.iter(|| black_box(decode_rar29(black_box(packed), size)));
        });

        let rar50_packed = OnceCell::new();
        group.bench_function(BenchmarkId::new("rar50_lz", chunk_label(size)), |b| {
            let packed = rar50_packed.get_or_init(|| {
                let packed = encode_rar50(&data);
                assert_eq!(decode_rar50(&packed, data.len()), data);
                packed
            });
            b.iter(|| black_box(decode_rar50(black_box(packed), size)));
        });
    }

    group.finish();
}

fn bench_literal_baseline(c: &mut Criterion) {
    let mut group = c.benchmark_group("literal_compression_baseline_by_chunk_size");

    for &size in CHUNK_SIZES {
        let data = payload(size);
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::new("rar29_literal", chunk_label(size)),
            &data,
            |b, data| {
                b.iter(|| {
                    black_box(
                        unpack29_encode_literals(black_box(data))
                            .expect("RAR 2.9 literal compression should succeed"),
                    )
                });
            },
        );
    }

    group.finish();
}

// The size sweep above uses greedy parsers. RAR5 writer levels 2..5 instead
// use the optimal parser and its tree finder, so time that path explicitly.
fn bench_optimal_compression(c: &mut Criterion) {
    let mut state = 0x1234_5678u32;
    let noise: Vec<_> = (0..128 * 1024)
        .map(|_| {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (state >> 31) as u8
        })
        .collect();
    let mut group = c.benchmark_group("rar50_optimal_parse");
    for (name, data) in [
        ("repeated_text", payload(128 * 1024)),
        ("two_symbol_noise", noise),
    ] {
        let options = Rar50EncodeOptions::new(128).with_optimal_parse(true);
        let checked = OnceCell::new();
        group.throughput(Throughput::Bytes(data.len() as u64));
        group.bench_with_input(BenchmarkId::from_parameter(name), &data, |b, data| {
            checked.get_or_init(|| check_optimal_round_trip(options, data));
            b.iter(|| {
                black_box(
                    Unpack50Encoder::with_options(options)
                        .encode_member(black_box(data), 0)
                        .expect("optimal compression should succeed"),
                )
            });
        });
    }
    group.finish();
}

// Expose per-pass preparation on short or literal-heavy inputs as well as
// the match-rich fixtures above. The unique-byte fixtures have no repeated
// four-byte prefix, while deterministic full-byte noise rarely has a match.
fn bench_optimal_setup(c: &mut Criterion) {
    let noise = |size| {
        let mut state = 0x8bad_f00du32;
        (0..size)
            .map(|_| {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                (state >> 24) as u8
            })
            .collect::<Vec<_>>()
    };
    let mut rare_repeat = noise(4 * 1024);
    rare_repeat.copy_within(128..144, 192);
    let mut group = c.benchmark_group("rar50_optimal_setup");
    for (name, data) in [
        ("unique_32B", (0..32).collect::<Vec<u8>>()),
        ("unique_256B", (0..=255).collect::<Vec<u8>>()),
        ("repeated_32B", b"abcd".repeat(8)),
        ("rare_repeat_4KiB", rare_repeat),
        ("literal_heavy_4KiB", noise(4 * 1024)),
        ("literal_heavy_64KiB", noise(64 * 1024)),
    ] {
        let options = Rar50EncodeOptions::new(128).with_optimal_parse(true);
        let checked = OnceCell::new();
        group.throughput(Throughput::Bytes(data.len() as u64));
        group.bench_with_input(BenchmarkId::from_parameter(name), &data, |b, data| {
            checked.get_or_init(|| check_optimal_round_trip(options, data));
            b.iter(|| {
                black_box(
                    Unpack50Encoder::with_options(options)
                        .encode_member(black_box(data), 0)
                        .expect("optimal compression should succeed"),
                )
            });
        });
    }
    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_compression, bench_decompression, bench_literal_baseline, bench_optimal_compression, bench_optimal_setup
);
criterion_main!(benches);

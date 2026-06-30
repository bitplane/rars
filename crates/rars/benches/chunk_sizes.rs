use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rars::codec::rar29::{
    unpack29_encode_literals, EncodeOptions as Rar29EncodeOptions, Unpack29, Unpack29Encoder,
};
use rars::codec::rar50::{
    DecodeMode, EncodeOptions as Rar50EncodeOptions, Unpack50Decoder, Unpack50Encoder,
};
use std::hint::black_box;

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

        let rar29_packed = encode_rar29(&data);
        let rar29_decoded = decode_rar29(&rar29_packed, data.len());
        assert_eq!(rar29_decoded, data);
        group.bench_with_input(
            BenchmarkId::new("rar29_lz", chunk_label(size)),
            &rar29_packed,
            |b, packed| {
                b.iter(|| black_box(decode_rar29(black_box(packed), size)));
            },
        );

        let rar50_packed = encode_rar50(&data);
        let rar50_decoded = decode_rar50(&rar50_packed, data.len());
        assert_eq!(rar50_decoded, data);
        group.bench_with_input(
            BenchmarkId::new("rar50_lz", chunk_label(size)),
            &rar50_packed,
            |b, packed| {
                b.iter(|| black_box(decode_rar50(black_box(packed), size)));
            },
        );
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

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_compression, bench_decompression, bench_literal_baseline
);
criterion_main!(benches);

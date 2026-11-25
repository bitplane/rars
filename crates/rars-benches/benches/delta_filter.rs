use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rars::codec::filters::{delta_decode, delta_encode};
use std::{hint::black_box, time::Duration};

const SIZE: usize = 1024 * 1024;
const CHANNELS: [usize; 7] = [1, 2, 3, 4, 8, 16, 32];

fn sample() -> Vec<u8> {
    let mut state = 0x9e37_79b9u32;
    (0..SIZE)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect()
}

fn decode(c: &mut Criterion) {
    let data = sample();
    let mut group = c.benchmark_group("delta_decode");
    group.throughput(Throughput::Bytes(SIZE as u64));
    for channels in CHANNELS {
        let encoded = delta_encode(&data, channels).unwrap();
        assert_eq!(delta_decode(&encoded, channels).unwrap(), data);
        group.bench_with_input(
            BenchmarkId::from_parameter(channels),
            &encoded,
            |b, encoded| {
                b.iter(|| delta_decode(black_box(encoded), channels).unwrap());
            },
        );
    }
    group.finish();
}

fn encode(c: &mut Criterion) {
    let data = sample();
    let mut group = c.benchmark_group("delta_encode");
    group.throughput(Throughput::Bytes(SIZE as u64));
    for channels in CHANNELS {
        group.bench_with_input(BenchmarkId::from_parameter(channels), &data, |b, data| {
            b.iter(|| delta_encode(black_box(data), channels).unwrap());
        });
    }
    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default()
        .sample_size(20)
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(2));
    targets = decode, encode
);
criterion_main!(benches);

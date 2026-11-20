use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use rars::rar50::{repair_inline_recovery_bytes, Archive};
use rars::{ArchiveVersion, Builder, WriterResources};
use std::{hint::black_box, time::Duration};

const SIZE: usize = 64 * 1024 * 1024;
const PERCENT: u64 = 5;

fn body() -> Vec<u8> {
    let mut state = 0x9e37_79b9_u32;
    (0..SIZE)
        .map(|_| {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (state >> 24) as u8
        })
        .collect()
}

// A stored member on one thread keeps the time on the recovery record itself.
fn builder() -> Builder {
    let mut builder = Builder::new(ArchiveVersion::Rar50)
        .store(true)
        .recovery_percent(Some(PERCENT));
    builder
        .add_bytes(b"body.bin".to_vec(), body(), None, None)
        .expect("benchmark member should be accepted");
    builder
}

fn single_thread_pool() -> rayon::ThreadPool {
    rayon::ThreadPoolBuilder::new()
        .num_threads(1)
        .build()
        .expect("benchmark pool should build")
}

fn bench_recovery_record(c: &mut Criterion) {
    let resources = WriterResources::new(1024 * 1024 * 1024);
    let builder = builder();
    let pool = single_thread_pool();
    let mut group = c.benchmark_group("rar50_recovery");
    group.throughput(Throughput::Bytes(SIZE as u64));
    group.bench_function("encode_5_percent", |b| {
        b.iter(|| {
            pool.install(|| {
                builder
                    .write_to(&mut std::io::sink(), &resources, None)
                    .expect("benchmark archive writing should succeed");
            });
        });
    });

    let mut archive = Vec::new();
    builder
        .write_to(&mut archive, &resources, None)
        .expect("benchmark archive writing should succeed");
    let header = Archive::parse(&archive)
        .expect("benchmark archive should parse")
        .files()
        .next()
        .expect("benchmark archive should hold the member")
        .block
        .offset;
    // Hits a quarter of the body apart land in separate shards.
    for (name, hits) in [("repair_one_shard", 1), ("repair_four_shards", 4)] {
        let mut damaged = archive.clone();
        for hit in 0..hits {
            damaged[header + hit * SIZE / 4] ^= 0xff;
        }
        group.bench_function(name, |b| {
            b.iter(|| {
                pool.install(|| {
                    let repaired = repair_inline_recovery_bytes(black_box(&damaged))
                        .expect("benchmark archive should repair");
                    assert_eq!(repaired, archive);
                });
            });
        });
    }
    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default()
        .sample_size(10)
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(10));
    targets = bench_recovery_record
);
criterion_main!(benches);

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use rars::rar50::{repair_inline_recovery_bytes, Archive};
use rars::recovery::rar3::reconstruct_data_volumes;
use rars::{ArchiveVersion, Builder, WriterResources};
use std::{hint::black_box, time::Duration};

const SIZE: usize = 64 * 1024 * 1024;
const PERCENT: u64 = 5;

fn body() -> Vec<u8> {
    random_bytes(SIZE, 0x9e37_79b9)
}

fn random_bytes(len: usize, seed: u32) -> Vec<u8> {
    let mut state = seed;
    (0..len)
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

const REV3_SHARD: usize = 4 * 1024 * 1024;
const REV3_DATA_VOLUMES: usize = 8;
const REV3_RECOVERY_VOLUMES: usize = 3;

// The decode is the same linear map whether or not the parity matches the
// data, so random recovery volumes time it as well as encoded ones.
fn bench_rev3_repair(c: &mut Criterion) {
    let shards: Vec<Vec<u8>> = (0..REV3_DATA_VOLUMES + REV3_RECOVERY_VOLUMES)
        .map(|index| random_bytes(REV3_SHARD, index as u32 + 1))
        .collect();
    let (data, recovery) = shards.split_at(REV3_DATA_VOLUMES);
    let recovery: Vec<(usize, &[u8])> = recovery
        .iter()
        .enumerate()
        .map(|(index, shard)| (index, shard.as_slice()))
        .collect();
    let mut group = c.benchmark_group("rar3_rev_repair");
    group.throughput(Throughput::Bytes((REV3_DATA_VOLUMES * REV3_SHARD) as u64));
    for (name, missing) in [("one_volume", 1), ("three_volumes", REV3_RECOVERY_VOLUMES)] {
        let volumes: Vec<Option<&[u8]>> = data
            .iter()
            .enumerate()
            .map(|(index, shard)| (index >= missing).then_some(shard.as_slice()))
            .collect();
        group.bench_function(name, |b| {
            b.iter(|| {
                reconstruct_data_volumes(black_box(&volumes), REV3_RECOVERY_VOLUMES, &recovery)
                    .expect("benchmark set should repair")
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
    targets = bench_recovery_record, bench_rev3_repair
);
criterion_main!(benches);

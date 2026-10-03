use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput};
use rars::rar50::{Archive, ArchiveEntry, Rar50Writer, WriterOptions};
use rars::{ArchiveReadOptions, ArchiveVersion, Builder, EntrySource, FeatureSet, WriterResources};
use std::hint::black_box;

const MEMBER_COUNT: usize = 8;
const MEMBER_SIZE: usize = 64 * 1024;

struct ArchiveFixture {
    names: Vec<Vec<u8>>,
    data: Vec<Vec<u8>>,
}

impl ArchiveFixture {
    fn new(member_count: usize, member_size: usize) -> Self {
        let names = (0..member_count)
            .map(|index| format!("file-{index:02}.bin").into_bytes())
            .collect();
        let data = (0..member_count)
            .map(|index| payload(member_size, index as u32))
            .collect();
        Self { names, data }
    }

    fn total_unpacked_size(&self) -> u64 {
        self.data.iter().map(|data| data.len() as u64).sum()
    }

    fn compressed_entries(&self) -> Vec<ArchiveEntry> {
        self.names
            .iter()
            .zip(&self.data)
            .map(|(name, data)| {
                ArchiveEntry::new(
                    name.clone(),
                    EntrySource::from_bytes(std::sync::Arc::<[u8]>::from(data.clone())),
                )
                .with_attributes(0x20)
                .with_host_os(3)
            })
            .collect()
    }
}

fn payload(size: usize, salt: u32) -> Vec<u8> {
    const PHRASE: &[u8] =
        b"rars parallel benchmark member with repeated text and changing literals\n";

    let mut out = Vec::with_capacity(size);
    let mut state = 0x9e37_79b9_u32 ^ salt.wrapping_mul(0x85eb_ca6b);
    while out.len() < size {
        out.extend_from_slice(PHRASE);
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        out.push((state >> 24) as u8);
        out.push((out.len() as u8).wrapping_add(salt as u8));
    }
    out.truncate(size);
    out
}

fn rar50_options() -> WriterOptions {
    WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only()).with_compression_level(3)
}

fn write_rar50_archive(fixture: &ArchiveFixture) -> Vec<u8> {
    Rar50Writer::new(rar50_options())
        .entries(fixture.compressed_entries())
        .finish()
        .expect("RAR 5 benchmark archive writing should succeed")
}

fn extract_rar50_archive(archive: &Archive) {
    archive
        .extract_to_parallel_buffered(ArchiveReadOptions::new(), |meta| {
            assert!(!meta.is_directory);
            Ok(Box::new(std::io::sink()))
        })
        .expect("RAR 5 parallel benchmark extraction should succeed");
}

fn thread_counts() -> Vec<usize> {
    let available = std::thread::available_parallelism().map_or(1, usize::from);
    if let Ok(requested) = std::env::var("RARS_BENCH_THREADS") {
        let mut counts: Vec<usize> = requested
            .split(',')
            .map(|count| {
                let count = count
                    .trim()
                    .parse()
                    .expect("RARS_BENCH_THREADS must contain integer thread counts");
                assert!(
                    count > 0 && count <= available,
                    "benchmark thread count exceeds available CPUs"
                );
                count
            })
            .collect();
        counts.sort_unstable();
        counts.dedup();
        return counts;
    }
    if available == 1 {
        vec![1]
    } else {
        vec![1, available.min(2)]
    }
}

fn thread_label(threads: usize) -> String {
    let available = std::thread::available_parallelism().map_or(1, usize::from);
    if threads == available && threads != 1 {
        format!("all_threads_{threads}")
    } else {
        format!("{threads}_thread")
    }
}

fn thread_pool(threads: usize) -> rayon::ThreadPool {
    rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .expect("benchmark Rayon pool should build")
}

fn bench_parallel_compression(c: &mut Criterion) {
    let fixture = ArchiveFixture::new(MEMBER_COUNT, MEMBER_SIZE);
    let entries = fixture.compressed_entries();
    let mut group = c.benchmark_group("parallel_rar50_compression");
    group.throughput(Throughput::Bytes(fixture.total_unpacked_size()));

    for threads in thread_counts() {
        let pool = thread_pool(threads);
        group.bench_with_input(
            BenchmarkId::from_parameter(thread_label(threads)),
            &threads,
            |b, _| {
                // Entry handles clone their Arc-backed sources in untimed setup.
                // Pool lifetime and caller payload copies are not compression.
                b.iter_batched(
                    || entries.clone(),
                    |entries| {
                        pool.install(|| {
                            black_box(
                                Rar50Writer::new(rar50_options())
                                    .entries(entries)
                                    .finish()
                                    .unwrap(),
                            )
                        });
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

fn bench_parallel_extraction(c: &mut Criterion) {
    let fixture = ArchiveFixture::new(MEMBER_COUNT, MEMBER_SIZE);
    let archive_bytes = write_rar50_archive(&fixture);
    let archive = Archive::parse(&archive_bytes).expect("benchmark archive should parse");
    extract_rar50_archive(&archive);

    let mut group = c.benchmark_group("parallel_rar50_extraction");
    group.throughput(Throughput::Bytes(fixture.total_unpacked_size()));

    for threads in thread_counts() {
        let pool = thread_pool(threads);
        group.bench_with_input(
            BenchmarkId::from_parameter(thread_label(threads)),
            &threads,
            |b, _| {
                b.iter(|| {
                    pool.install(|| {
                        extract_rar50_archive(black_box(&archive));
                    });
                });
            },
        );
    }

    group.finish();
}

fn bench_setup(c: &mut Criterion) {
    let fixture = ArchiveFixture::new(MEMBER_COUNT, MEMBER_SIZE);
    c.bench_function("rar50_input_copy_and_entry_setup", |b| {
        b.iter(|| black_box(fixture.compressed_entries()));
    });
    let mut group = c.benchmark_group("parallel_pool_setup");
    for threads in thread_counts() {
        group.bench_with_input(
            BenchmarkId::from_parameter(threads),
            &threads,
            |b, &threads| {
                b.iter(|| black_box(thread_pool(threads)));
            },
        );
    }
    group.finish();
}

// Filter search makes several optimal parses of these numeric samples. Unlike
// the repeated-text fixture, it spends substantial time pricing short matches
// and exposes overhead in the parser's per-candidate helpers.
fn bench_candidate_pricing(c: &mut Criterion) {
    let data: Vec<_> = (0..32768u32)
        .flat_map(|n| ((n * 71) % 32749).to_le_bytes())
        .collect();
    let mut builder = Builder::new(ArchiveVersion::Rar50)
        .store(false)
        .compression_level(Some(3));
    for index in 0..4 {
        builder
            .add_bytes(
                format!("samples-{index}.bin").into_bytes(),
                data.clone(),
                None,
                None,
            )
            .expect("benchmark member should be accepted");
    }
    let resources = WriterResources::new(256 * 1024 * 1024);
    let pool = thread_pool(thread_counts().into_iter().max().unwrap());
    let mut group = c.benchmark_group("rar50_candidate_pricing");
    group.throughput(Throughput::Bytes(4 * data.len() as u64));
    group.bench_function("numeric_samples", |b| {
        b.iter(|| {
            pool.install(|| {
                builder
                    .write_to(&mut std::io::sink(), &resources, None)
                    .expect("benchmark archive writing should succeed");
            });
        });
    });
    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_parallel_compression, bench_parallel_extraction, bench_candidate_pricing, bench_setup
);
criterion_main!(benches);

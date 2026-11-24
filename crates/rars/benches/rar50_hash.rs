use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rars::rar50::{ArchiveEntry, Rar50Writer, WriterOptions};
use rars::{ArchiveReader, ArchiveVersion, EntrySource, FeatureSet};
use std::{hint::black_box, sync::Arc, time::Duration};

fn hashes(c: &mut Criterion) {
    let mut group = c.benchmark_group("rar50_blake2sp_verification");
    for size in [512, 4096, 1024 * 1024, 32 * 1024 * 1024] {
        let data: Arc<[u8]> = (0..size).map(|i| (i % 251) as u8).collect();
        // Preparing, parsing and validating the stored archive are untimed.
        // Use the public member hash verifier to exercise the production hash
        // without conflating it with compression or copying decoded output.
        let mut features = FeatureSet::store_only();
        features.blake2sp = true;
        let bytes = Rar50Writer::new(WriterOptions::new(ArchiveVersion::Rar50, features))
            .entry(ArchiveEntry::new(
                b"payload".to_vec(),
                EntrySource::from_bytes(Arc::clone(&data)),
            ))
            .finish()
            .expect("hash benchmark archive should encode");
        let archive = ArchiveReader::read_owned(bytes).expect("benchmark archive should parse");
        let raw = archive.as_rar50().unwrap();
        let file = raw.files().next().unwrap();
        assert_eq!(file.hash.as_ref().unwrap().hash_type, 0);
        assert_eq!(file.hash.as_ref().unwrap().data.len(), 32);
        file.verify_hash(&data).unwrap();
        assert_eq!(&*archive.read_member_at(0, None).unwrap().unwrap(), &*data);

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, data| {
            b.iter(|| {
                black_box(file)
                    .verify_hash(black_box(data))
                    .expect("hash should match");
            });
        });
    }
    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default()
        .sample_size(15)
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(3));
    targets = hashes
);
criterion_main!(benches);

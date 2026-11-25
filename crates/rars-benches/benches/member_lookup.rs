use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use rars::{ArchiveReader, ArchiveVersion, Builder};
use std::hint::black_box;

fn bench_member_lookup(c: &mut Criterion) {
    let mut group = c.benchmark_group("member_metadata_lookup");
    for count in [16, 1024] {
        let mut builder = Builder::new(ArchiveVersion::Rar50).store(true);
        for index in 0..count {
            builder
                .add_bytes(
                    format!("member-{index}").into_bytes(),
                    vec![0; 4],
                    None,
                    None,
                )
                .unwrap();
        }
        let archive = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
        let index = archive.index();
        let last_name = format!("member-{}", count - 1).into_bytes();
        group.bench_with_input(BenchmarkId::new("owned_at", count), &count, |b, count| {
            b.iter(|| black_box(archive.members().nth(black_box(*count - 1))))
        });
        group.bench_with_input(
            BenchmarkId::new("borrowed_at", count),
            &count,
            |b, count| b.iter(|| black_box(archive.member_refs().nth(black_box(*count - 1)))),
        );
        group.bench_with_input(BenchmarkId::new("indexed_at", count), &count, |b, count| {
            b.iter(|| black_box(index.get(black_box(*count - 1))))
        });
        group.bench_with_input(BenchmarkId::new("scanned_name", count), &count, |b, _| {
            b.iter(|| {
                black_box(
                    archive
                        .member_refs()
                        .enumerate()
                        .filter(|(_, member)| member.name_bytes() == black_box(&last_name))
                        .map(|(index, _)| index)
                        .last(),
                )
            })
        });
        group.bench_with_input(BenchmarkId::new("indexed_name", count), &count, |b, _| {
            b.iter(|| black_box(index.payload_index_of(black_box(&last_name))))
        });
        // Index creation is paid once and kept separate from repeated lookup.
        group.bench_with_input(BenchmarkId::new("index_setup", count), &count, |b, _| {
            b.iter(|| black_box(archive.index()))
        });
    }
    group.finish();
}

criterion_group!(benches, bench_member_lookup);
criterion_main!(benches);

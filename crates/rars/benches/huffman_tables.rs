use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use rars::codec::rar50::HuffmanTable;
use std::hint::black_box;

fn tables(c: &mut Criterion) {
    let mut group = c.benchmark_group("huffman_tables");
    // Fixed decoder inputs, including an incomplete main alphabet and a deep
    // sparse tree. Input generation and the checkpoint source are untimed.
    let mut sparse = vec![0; 306];
    for (index, length) in (1..=15).chain([15]).enumerate() {
        sparse[index * 19] = length;
    }
    for (name, lengths) in [
        ("main", vec![9; 306]),
        ("align", vec![4; 16]),
        ("sparse", sparse),
    ] {
        group.bench_with_input(BenchmarkId::new("build", name), &lengths, |b, lengths| {
            b.iter(|| black_box(HuffmanTable::from_lengths(black_box(lengths)).unwrap()));
        });
        let table = HuffmanTable::from_lengths(&lengths).unwrap();
        group.bench_with_input(BenchmarkId::new("checkpoint", name), &table, |b, table| {
            b.iter(|| black_box(black_box(table).clone()));
        });
    }
    group.finish();
}

criterion_group!(benches, tables);
criterion_main!(benches);

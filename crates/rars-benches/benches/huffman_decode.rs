use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rars::codec::rar50::{decode_literal_only, encode_literal_only, DecodedChunk, Unpack50Decoder};
use std::{hint::black_box, time::Duration};

const MEMBER_SIZE: usize = 128 * 1024;
const DICTIONARY_SIZE: usize = 4 * 1024 * 1024;

fn literals(c: &mut Criterion) {
    let mut group = c.benchmark_group("rar50_huffman_literals");
    group.throughput(Throughput::Bytes(MEMBER_SIZE as u64));
    for alphabet in [1, 2, 16, 256] {
        let data: Vec<_> = (0..MEMBER_SIZE)
            .map(|index| (index % alphabet) as u8)
            .collect();
        // Force literals so match-copy throughput cannot hide short-code or
        // eight-bit Huffman decoding changes. Generate and validate untimed.
        let packed = encode_literal_only(&data, 0).unwrap();
        eprintln!(
            "fixture alphabet={alphabet}: {} decoded bytes, {} packed bytes, packed crc32 {:08x}",
            data.len(),
            packed.len(),
            rars::crc32::crc32(&packed)
        );
        // Export exact benchmark inputs only when explicitly requested. This
        // supports cross-revision byte identity checks outside timed work.
        if let Some(directory) = std::env::var_os("RARS_HUFFMAN_FIXTURE_DIR") {
            let directory = std::path::PathBuf::from(directory);
            std::fs::create_dir_all(&directory).unwrap();
            std::fs::write(directory.join(format!("alphabet-{alphabet}.bin")), &data).unwrap();
            std::fs::write(
                directory.join(format!("alphabet-{alphabet}.packed")),
                &packed,
            )
            .unwrap();
        }
        assert_eq!(decode_literal_only(&packed, 0, data.len()).unwrap(), data);
        let mut decoded = Vec::new();
        Unpack50Decoder::new()
            .decode_member_from_reader_with_dictionary_to_sink(
                &mut packed.as_slice(),
                0,
                data.len(),
                DICTIONARY_SIZE,
                false,
                |chunk| {
                    match chunk {
                        DecodedChunk::Bytes(bytes) => decoded.extend_from_slice(bytes),
                        DecodedChunk::Repeated { byte, len } => {
                            decoded.resize(decoded.len() + len, byte)
                        }
                    }
                    Ok::<_, std::convert::Infallible>(())
                },
            )
            .unwrap();
        assert_eq!(decoded, data);
        group.bench_with_input(
            BenchmarkId::new("buffered", alphabet),
            &packed,
            |b, packed| {
                b.iter(|| {
                    black_box(decode_literal_only(black_box(packed), 0, MEMBER_SIZE).unwrap())
                });
            },
        );
        group.bench_with_input(
            BenchmarkId::new("streaming", alphabet),
            &packed,
            |b, packed| {
                b.iter(|| {
                    Unpack50Decoder::new()
                        .decode_member_from_reader_with_dictionary_to_sink(
                            &mut black_box(packed).as_slice(),
                            0,
                            MEMBER_SIZE,
                            DICTIONARY_SIZE,
                            false,
                            |chunk| {
                                black_box(chunk);
                                Ok::<_, std::convert::Infallible>(())
                            },
                        )
                        .unwrap();
                });
            },
        );
    }
    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default()
        .sample_size(15)
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(2));
    targets = literals
);
criterion_main!(benches);

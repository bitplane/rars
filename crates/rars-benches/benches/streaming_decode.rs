use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rars::rar50::{ArchiveEntry, FilterPolicy, Rar50Writer, WriterOptions};
use rars::{Archive, ArchiveReadOptions, ArchiveReader, ArchiveVersion, EntrySource, FeatureSet};
use std::{cell::OnceCell, hint::black_box, sync::Arc, time::Duration};

const MEMBER_SIZE: usize = 2 * 1024 * 1024;

fn periodic_payload(period: usize) -> Vec<u8> {
    let mut state = 0x9e37_79b9_u32;
    let pattern: Vec<_> = (0..period)
        .map(|_| {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (state >> 24) as u8
        })
        .collect();
    pattern.into_iter().cycle().take(MEMBER_SIZE).collect()
}

fn mixed_payload() -> Vec<u8> {
    const PHRASE: &[u8] = b"streaming decoder benchmark with repeated text and changing literals\n";
    let mut data = Vec::with_capacity(MEMBER_SIZE + PHRASE.len());
    let mut state = 0x9e37_79b9_u32;
    while data.len() < MEMBER_SIZE {
        data.extend_from_slice(PHRASE);
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        data.push((state >> 24) as u8);
        data.push((data.len() & 0xff) as u8);
    }
    data.truncate(MEMBER_SIZE);
    data
}

fn fixture(name: &str, data: Vec<u8>) -> Archive {
    let source = EntrySource::from_bytes(Arc::<[u8]>::from(data.clone()));
    let bytes = Rar50Writer::new(
        WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only())
            .with_compression_level(3),
    )
    .entry(ArchiveEntry::new(b"payload".to_vec(), source))
    .filter_policy(FilterPolicy::None)
    .finish()
    .expect("streaming benchmark archive should encode");
    eprintln!(
        "fixture {name}: {} archive bytes, crc32 {:08x}",
        bytes.len(),
        rars::crc32::crc32(&bytes)
    );
    let archive = ArchiveReader::read_owned(bytes).expect("benchmark archive should parse");
    assert_eq!(archive.read_member_at(0, None).unwrap().unwrap(), data);
    assert_eq!(
        archive
            .read_member_at_with_options(
                0,
                ArchiveReadOptions::new().with_rar50_buffered_decode_limit(0),
            )
            .expect("benchmark archive should stream and verify its checksum")
            .unwrap(),
        data
    );
    archive
}

fn payload(name: &str) -> Vec<u8> {
    match name {
        "period_3" => periodic_payload(3),
        "period_64" => periodic_payload(64),
        "period_4096" => periodic_payload(4096),
        "mixed_text" => mixed_payload(),
        _ => unreachable!("unknown streaming benchmark payload {name}"),
    }
}

fn decode(c: &mut Criterion, streaming: bool) {
    let mut group = c.benchmark_group(if streaming {
        "rar50_streaming_decode"
    } else {
        "rar50_buffered_decode"
    });
    let options = if streaming {
        ArchiveReadOptions::new().with_rar50_buffered_decode_limit(0)
    } else {
        ArchiveReadOptions::new()
    };
    group.throughput(Throughput::Bytes(MEMBER_SIZE as u64));
    for name in ["period_3", "period_64", "period_4096", "mixed_text"] {
        // Archive generation, parsing and byte-for-byte validation are untimed,
        // and wait until the case runs: a filtered run (nextest runs each case
        // in its own process) builds only the archive it measures.
        // An explicit zero buffering limit selects the production streaming
        // reader on this bounded member instead of its <=512 MiB buffered path.
        let archive = OnceCell::new();
        group.bench_function(BenchmarkId::from_parameter(name), |b| {
            let archive = archive.get_or_init(|| {
                let archive = fixture(name, payload(name));
                archive.test_with_options(options).unwrap();
                archive
            });
            b.iter(|| {
                black_box(archive)
                    .test_with_options(options)
                    .expect("decode should preserve integrity");
            });
        });
    }
    group.finish();
}

fn streaming_decode(c: &mut Criterion) {
    decode(c, true);
}

fn buffered_decode(c: &mut Criterion) {
    decode(c, false);
}

criterion_group!(
    name = benches;
    config = Criterion::default()
        .sample_size(15)
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(3));
    targets = streaming_decode, buffered_decode
);
criterion_main!(benches);

// Generate and verify fixtures outside timed work. Fresh decoders include table
// construction, so tiny members expose lookup setup costs. The audio fixture
// must actually select an audio block rather than silently measuring LZ.
use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use rars::codec::rar20::{
    unpack20_encode_auto_with_options, EncodeOptions, Unpack20, Unpack20Encoder,
};
use std::{hint::black_box, time::Duration};

fn decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("rar20_decode");

    for kind in [
        "period3",
        "period64",
        "short",
        "literals",
        "tiny",
        "one",
        "audio",
        "audio_noise",
    ] {
        let size = match kind {
            "tiny" => 128,
            "one" => 1,
            "audio" | "audio_noise" => 32768,
            _ => 256 * 1024,
        };
        let mut random = 0x1234_5678u32;
        let mut next = || {
            random ^= random << 13;
            random ^= random >> 17;
            random ^= random << 5;
            random as u8
        };
        let data: Vec<u8> = match kind {
            "period3" | "period64" => {
                let n = if kind == "period3" { 3 } else { 64 };
                let pattern: Vec<_> = (0..n).map(|_| next()).collect();
                pattern.into_iter().cycle().take(size).collect()
            }
            "audio" => (0..8192i16)
                .flat_map(|sample| {
                    let l = sample.wrapping_mul(3).wrapping_add(200);
                    let r = sample.wrapping_mul(3).wrapping_sub(200);
                    [l.to_le_bytes(), r.to_le_bytes()].concat()
                })
                .collect(),
            "audio_noise" => (0..8192)
                .flat_map(|sample| {
                    let wave = ((sample % 512) as i16 - 256) * 32;
                    let l = wave + i16::from(next() & 31) - 16;
                    let r = wave + i16::from(next() & 31) - 216;
                    [l.to_le_bytes(), r.to_le_bytes()].concat()
                })
                .collect(),
            "short" => (0..size / 4)
                .flat_map(|_| {
                    let x = next();
                    [x, x, x, x ^ 0x80]
                })
                .collect(),
            _ => (0..size).map(|_| next()).collect(),
        };
        let mut options =
            EncodeOptions::new(if kind == "literals" { 0 } else { 16 }).with_try_audio(false);
        if kind == "short" {
            options = options.with_max_match_distance(1);
        }
        let packed = if kind.starts_with("audio") {
            let p = unpack20_encode_auto_with_options(&data, options.with_try_audio(true)).unwrap();
            assert_ne!(p[0] & 0x80, 0);
            p
        } else {
            Unpack20Encoder::with_options(options)
                .encode_member(&data)
                .unwrap()
        };
        assert_eq!(Unpack20::new().decode_member(&packed, size).unwrap(), data);
        eprintln!(
            "fixture {kind}: {} decoded bytes, {} packed bytes, crc32 {:08x}",
            data.len(),
            packed.len(),
            rars::crc32::crc32(&packed)
        );
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(kind, |b| {
            b.iter(|| {
                black_box(
                    Unpack20::new()
                        .decode_member(black_box(&packed), size)
                        .unwrap(),
                )
            });
        });
    }
    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default()
        .sample_size(15)
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(2));
    targets = decode
);
criterion_main!(benches);

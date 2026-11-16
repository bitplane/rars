use rars::rar15_40::{
    write_compressed_volumes, write_compressed_volumes_to, CollectedVolumes, FileEntry,
    VolumeOutput, VolumeSink, WriterOptions,
};
use rars::{ArchiveVersion, FeatureSet};

fn data() -> Vec<u8> {
    let mut state = 0x1234_5678u32;
    (0..40_000u32)
        .map(|i| {
            state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            if i % 5 == 0 {
                (state >> 24) as u8
            } else {
                b"the quick brown fox "[(i % 20) as usize]
            }
        })
        .collect()
}

fn noise() -> Vec<u8> {
    let mut state = 0x9e37_79b9u32;
    (0..9_000)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect()
}

fn entry<'a>(data: &'a [u8], password: Option<&'a [u8]>) -> FileEntry<'a> {
    FileEntry {
        name: b"data.bin",
        data,
        file_time: 0x5a21_3c4d,
        file_attr: 0x20,
        host_os: 2,
        password,
        file_comment: None,
    }
}

fn fingerprint(volumes: &[Vec<u8>]) -> Vec<(usize, u32)> {
    volumes
        .iter()
        .map(|volume| (volume.len(), crc32fast::hash(volume)))
        .collect()
}

type Case<'a> = (
    ArchiveVersion,
    FeatureSet,
    Option<&'a [u8]>,
    &'a [u8],
    &'static [(usize, u32)],
);

fn features(solid: bool, header_encryption: bool) -> FeatureSet {
    let mut features = FeatureSet::store_only();
    features.solid = solid;
    features.header_encryption = header_encryption;
    features
}

// Lengths and CRCs of what the writer produced while it collected every volume.
#[test]
fn compressed_volumes_match_the_collecting_writer_byte_for_byte() {
    type Golden = &'static [(usize, u32)];
    let data = data();
    let noise = noise();
    let plain = FeatureSet::store_only();
    let rar29_family: Golden = &[(4000, 2211979389), (4000, 859169878), (1610, 950802394)];
    let cases: [Case; 9] = [
        (
            ArchiveVersion::Rar15,
            plain,
            None,
            &data,
            &[
                (4000, 2890962626),
                (4000, 3154893835),
                (4000, 1831939250),
                (4000, 2634338861),
                (1528, 24330193),
            ],
        ),
        (
            ArchiveVersion::Rar20,
            plain,
            None,
            &data,
            &[
                (4000, 916672814),
                (4000, 954759445),
                (4000, 1693362357),
                (1691, 1194417463),
            ],
        ),
        (ArchiveVersion::Rar29, plain, None, &data, rar29_family),
        (ArchiveVersion::Rar30, plain, None, &data, rar29_family),
        (ArchiveVersion::Rar40, plain, None, &data, rar29_family),
        // Coded through the solid encoder since sets took several members, as
        // a plain solid archive codes it.
        (
            ArchiveVersion::Rar40,
            features(true, false),
            None,
            &data,
            &[(4000, 3767647119), (4000, 1883229518), (706, 3369210247)],
        ),
        (
            ArchiveVersion::Rar15,
            plain,
            Some(b"secret"),
            &data,
            &[
                (4000, 3260565064),
                (4000, 396586866),
                (4000, 1262848883),
                (4000, 1844390586),
                (1528, 266564067),
            ],
        ),
        (
            ArchiveVersion::Rar20,
            plain,
            Some(b"secret"),
            &data,
            &[
                (4000, 2139939348),
                (4000, 3778798388),
                (4000, 2116630113),
                (1696, 3357619074),
            ],
        ),
        (
            ArchiveVersion::Rar40,
            plain,
            None,
            &noise,
            &[(4000, 3633366775), (4000, 3135306252), (1432, 3705095565)],
        ),
    ];
    for (target, features, password, input, golden) in cases {
        let volumes = write_compressed_volumes(
            entry(input, password),
            WriterOptions::new(target, features),
            4000,
        )
        .unwrap();
        assert_eq!(
            fingerprint(&volumes),
            golden,
            "{target:?} solid={} password={}",
            features.solid,
            password.is_some()
        );
    }
}

#[derive(Default)]
struct Calls(Vec<String>, CollectedVolumes);

impl VolumeSink for Calls {
    fn expect_volumes(&mut self, total: u64) -> rars::Result<()> {
        self.0.push(format!("expect {total}"));
        Ok(())
    }

    fn start_volume(&mut self, index: u64) -> rars::Result<Box<dyn VolumeOutput>> {
        self.0.push(format!("start {index}"));
        self.1.start_volume(index)
    }

    fn finish_volume(&mut self, index: u64, len: u64) -> rars::Result<()> {
        self.0.push(format!("finish {index} {len}"));
        Ok(())
    }
}

#[test]
fn each_volume_is_finished_before_the_next_starts() {
    let data = data();
    let mut sink = Calls::default();
    write_compressed_volumes_to(
        entry(&data, None),
        WriterOptions::new(ArchiveVersion::Rar40, FeatureSet::store_only()),
        4000,
        &mut sink,
        None,
    )
    .unwrap();
    assert_eq!(
        sink.0,
        [
            "expect 3",
            "start 0",
            "finish 0 4000",
            "start 1",
            "finish 1 4000",
            "start 2",
            "finish 2 1610",
        ]
    );
}

fn extract(volumes: &[Vec<u8>], password: &[u8]) -> Vec<u8> {
    let archives: Vec<_> = volumes
        .iter()
        .map(|volume| rars::rar15_40::Archive::parse_with_password(volume, Some(password)).unwrap())
        .collect();
    let out = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    rars::rar15_40::extract_volumes_to(
        &archives,
        rars::ArchiveReadOptions::with_optional_password(Some(password)),
        |_| {
            struct Shared(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
            impl std::io::Write for Shared {
                fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                    self.0.lock().unwrap().extend_from_slice(buf);
                    Ok(buf.len())
                }
                fn flush(&mut self) -> std::io::Result<()> {
                    Ok(())
                }
            }
            Ok(Box::new(Shared(out.clone())))
        },
    )
    .unwrap();
    std::sync::Arc::try_unwrap(out)
        .unwrap()
        .into_inner()
        .unwrap()
}

#[test]
fn encrypted_compressed_volumes_extract_to_the_source() {
    let data = data();
    for (header_encryption, solid) in [(false, false), (true, false), (true, true)] {
        for target in [ArchiveVersion::Rar30, ArchiveVersion::Rar40] {
            let mut sink = CollectedVolumes::new();
            write_compressed_volumes_to(
                entry(&data, Some(b"secret")),
                WriterOptions::new(target, features(solid, header_encryption)),
                4000,
                &mut sink,
                None,
            )
            .unwrap();
            let volumes = sink.take();
            assert!(volumes.len() > 1);
            assert!(volumes.iter().all(|volume| volume.len() <= 4000));
            assert_eq!(
                extract(&volumes, b"secret"),
                data,
                "{target:?} header_encryption={header_encryption} solid={solid}"
            );
        }
    }
}

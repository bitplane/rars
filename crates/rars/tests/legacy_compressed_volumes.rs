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

fn features(solid: bool, header_encryption: bool) -> FeatureSet {
    let mut features = FeatureSet::store_only();
    features.solid = solid;
    features.header_encryption = header_encryption;
    features
}

/// Lengths and CRCs of what the writer produced while it collected every
/// volume, one line per case, in `tests/fixtures/golden`.
///
/// Every set carries a producer record naming the library version, so a version
/// bump changes these. The release hook regenerates them with the RAR 5
/// fixtures: `RARS_BLESS_GOLDEN=1 cargo test -p rars --test legacy_compressed_volumes`.
#[test]
fn compressed_volumes_match_the_collecting_writer_byte_for_byte() {
    let data = data();
    let noise = noise();
    let plain = FeatureSet::store_only();
    type Case<'a> = (ArchiveVersion, FeatureSet, Option<&'a [u8]>, &'a [u8]);
    let cases: [Case; 9] = [
        (ArchiveVersion::Rar15, plain, None, &data),
        (ArchiveVersion::Rar20, plain, None, &data),
        (ArchiveVersion::Rar29, plain, None, &data),
        (ArchiveVersion::Rar30, plain, None, &data),
        (ArchiveVersion::Rar40, plain, None, &data),
        // Coded through the solid encoder since sets took several members, as
        // a plain solid archive codes it.
        (ArchiveVersion::Rar40, features(true, false), None, &data),
        (ArchiveVersion::Rar15, plain, Some(b"secret"), &data),
        (ArchiveVersion::Rar20, plain, Some(b"secret"), &data),
        (ArchiveVersion::Rar40, plain, None, &noise),
    ];
    let mut produced = String::new();
    for (index, (target, features, password, input)) in cases.into_iter().enumerate() {
        let volumes = write_compressed_volumes(
            entry(input, password),
            WriterOptions::new(target, features),
            4000,
        )
        .unwrap();
        let fingerprint: Vec<String> = volumes
            .iter()
            .map(|volume| format!("{}:{}", volume.len(), crc32fast::hash(volume)))
            .collect();
        produced.push_str(&format!(
            "{index} {target:?} solid={} encrypted={} {}\n",
            features.solid,
            password.is_some(),
            fingerprint.join(" ")
        ));
    }

    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/golden/legacy_compressed_volumes.txt");
    if std::env::var_os("RARS_BLESS_GOLDEN").is_some() {
        std::fs::write(&path, &produced).expect("write golden fixture");
        return;
    }
    let expected = std::fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "missing golden fixture {}: {error}\n\
             regenerate with RARS_BLESS_GOLDEN=1 cargo test -p rars --test legacy_compressed_volumes",
            path.display()
        )
    });
    for (expected, produced) in expected.lines().zip(produced.lines()) {
        assert_eq!(
            produced, expected,
            "if this change is intentional, regenerate with \
             RARS_BLESS_GOLDEN=1 cargo test -p rars --test legacy_compressed_volumes"
        );
    }
    assert_eq!(expected.lines().count(), produced.lines().count());
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

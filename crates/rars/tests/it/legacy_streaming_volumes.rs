use rars::rar15_40::{
    write_stored_volumes_to, CollectedVolumes, EntrySource, StreamingEntry, WriterOptions,
};
use rars::{ArchiveVersion, FeatureSet, WriterResources};

fn data() -> Vec<u8> {
    (0..10_003u32).map(|i| (i * 31 + i / 7) as u8).collect()
}

fn entry(source: EntrySource, password: Option<&[u8]>) -> StreamingEntry {
    let entry = StreamingEntry::new(b"data.bin".to_vec(), source)
        .with_file_time(0x5a21_3c4d)
        .with_file_attr(0x20)
        .with_host_os(2);
    match password {
        Some(password) => entry.with_password(password.to_vec()),
        None => entry,
    }
}

fn stream(
    entry: &StreamingEntry,
    options: WriterOptions,
    volume_size: usize,
) -> rars::Result<Vec<Vec<u8>>> {
    let mut sink = CollectedVolumes::new();
    write_stored_volumes_to(
        entry,
        options,
        volume_size,
        &mut sink,
        &WriterResources::default(),
        None,
    )?;
    Ok(sink.take())
}

/// Lengths and CRCs of what the in-memory writer produced before it streamed,
/// updated when later volumes moved the producer record after their files; one
/// line per case, in `tests/fixtures/golden`.
///
/// Every set carries a producer record naming the library version, so a version
/// bump changes these. The release hook regenerates them with the RAR 5
/// fixtures: `RARS_BLESS_GOLDEN=1 cargo test -p rars --test it legacy_streaming_volumes::`.
#[test]
fn streamed_volumes_match_the_in_memory_writer_byte_for_byte() {
    let mut cases = Vec::new();
    for password in [None, Some(&b"secret"[..])] {
        let targets: &[ArchiveVersion] = match password {
            None => &[
                ArchiveVersion::Rar15,
                ArchiveVersion::Rar20,
                ArchiveVersion::Rar29,
                ArchiveVersion::Rar30,
                ArchiveVersion::Rar40,
            ],
            Some(_) => &[ArchiveVersion::Rar15, ArchiveVersion::Rar20],
        };
        for &target in targets {
            for volume_size in [3000, 20_000] {
                cases.push((target, password, volume_size));
            }
        }
    }
    let mut produced = String::new();
    for (index, (target, password, volume_size)) in cases.into_iter().enumerate() {
        let entry = entry(EntrySource::from_bytes(data()), password);
        let options = WriterOptions::new(target, FeatureSet::store_only());
        let volumes = stream(&entry, options, volume_size).unwrap();
        let fingerprint: Vec<String> = volumes
            .iter()
            .map(|volume| format!("{}:{}", volume.len(), rars::crc32::crc32(volume)))
            .collect();
        produced.push_str(&format!(
            "{index} {target:?} encrypted={} size={volume_size} {}\n",
            password.is_some(),
            fingerprint.join(" ")
        ));
    }

    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/golden/legacy_streaming_volumes.txt");
    if std::env::var_os("RARS_BLESS_GOLDEN").is_some() {
        std::fs::write(&path, &produced).expect("write golden fixture");
        return;
    }
    let expected = std::fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "missing golden fixture {}: {error}\n\
             regenerate with RARS_BLESS_GOLDEN=1 cargo test -p rars --test it legacy_streaming_volumes::",
            path.display()
        )
    });
    for (expected, produced) in expected.lines().zip(produced.lines()) {
        assert_eq!(
            produced, expected,
            "if this change is intentional, regenerate with \
             RARS_BLESS_GOLDEN=1 cargo test -p rars --test it legacy_streaming_volumes::"
        );
    }
    assert_eq!(expected.lines().count(), produced.lines().count());
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
fn encrypted_streamed_volumes_extract_to_the_source() {
    for header_encryption in [false, true] {
        for target in [
            ArchiveVersion::Rar29,
            ArchiveVersion::Rar30,
            ArchiveVersion::Rar40,
        ] {
            let mut features = FeatureSet::store_only();
            features.header_encryption = header_encryption;
            let entry = entry(EntrySource::from_bytes(data()), Some(b"secret"));
            let volumes = stream(&entry, WriterOptions::new(target, features), 3000).unwrap();
            assert!(volumes.len() > 1);
            assert!(volumes.iter().all(|volume| volume.len() <= 3000));
            assert_eq!(
                extract(&volumes, b"secret"),
                data(),
                "{target:?} {header_encryption}"
            );
        }
    }
}

#[test]
fn the_source_is_read_once() {
    let opens = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let source = {
        let opens = opens.clone();
        EntrySource::from_opener(10_003, move || {
            opens.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(Box::new(std::io::Cursor::new(data())))
        })
    };
    for (target, password) in [
        (ArchiveVersion::Rar40, None),
        (ArchiveVersion::Rar30, Some(&b"secret"[..])),
    ] {
        opens.store(0, std::sync::atomic::Ordering::SeqCst);
        let options = WriterOptions::new(target, FeatureSet::store_only());
        let volumes = stream(&entry(source.clone(), password), options, 3000).unwrap();
        assert_eq!(volumes.len(), 4);
        assert_eq!(
            opens.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "{target:?}"
        );
    }
}

#[test]
fn a_source_shorter_than_it_claimed_is_refused() {
    let source = EntrySource::from_opener(10_003, || {
        Ok(Box::new(std::io::Cursor::new(data()[..9_000].to_vec())))
    });
    let options = WriterOptions::new(ArchiveVersion::Rar40, FeatureSet::store_only());
    let error = stream(&entry(source, None), options, 3000).unwrap_err();
    assert_eq!(error.kind(), rars::ErrorKind::SourceChanged);
}

#[test]
fn every_finished_volume_reports_the_size_of_the_set() {
    struct Totals(std::sync::Mutex<Vec<(usize, Option<usize>)>>);
    impl rars::WriteProgress for Totals {
        fn report(&self, event: rars::WriteProgressEvent<'_>) {
            if let rars::WriteProgressEvent::VolumeFinished {
                volume_index,
                total_volumes,
                ..
            } = event
            {
                self.0.lock().unwrap().push((volume_index, total_volumes));
            }
        }
    }
    let totals = Totals(std::sync::Mutex::new(Vec::new()));
    let mut sink = CollectedVolumes::new();
    write_stored_volumes_to(
        &entry(EntrySource::from_bytes(data()), None),
        WriterOptions::new(ArchiveVersion::Rar40, FeatureSet::store_only()),
        3000,
        &mut sink,
        &WriterResources::default(),
        Some(&totals),
    )
    .unwrap();
    assert_eq!(
        totals.0.into_inner().unwrap(),
        [(0, Some(4)), (1, Some(4)), (2, Some(4)), (3, Some(4))]
    );
}

#[test]
fn the_sink_hears_the_set_size_before_the_first_volume() {
    #[derive(Default)]
    struct Calls(Vec<String>, CollectedVolumes);
    impl rars::rar15_40::VolumeSink for Calls {
        fn expect_volumes(&mut self, total: u64) -> rars::Result<()> {
            self.0.push(format!("expect {total}"));
            Ok(())
        }
        fn start_volume(
            &mut self,
            index: u64,
        ) -> rars::Result<Box<dyn rars::rar15_40::VolumeOutput>> {
            self.0.push(format!("start {index}"));
            self.1.start_volume(index)
        }
    }
    let mut sink = Calls::default();
    write_stored_volumes_to(
        &entry(EntrySource::from_bytes(data()), None),
        WriterOptions::new(ArchiveVersion::Rar40, FeatureSet::store_only()),
        3000,
        &mut sink,
        &WriterResources::default(),
        None,
    )
    .unwrap();
    assert_eq!(
        sink.0,
        ["expect 4", "start 0", "start 1", "start 2", "start 3"]
    );
}

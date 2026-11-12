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

// Lengths and CRCs of what the in-memory writer produced before it streamed.
#[test]
fn streamed_volumes_match_the_in_memory_writer_byte_for_byte() {
    type Golden = &'static [(usize, u32)];
    let cases: [(ArchiveVersion, Option<&[u8]>, usize, Golden); 14] = [
        (
            ArchiveVersion::Rar15,
            None,
            3000,
            &[
                (0xbb8, 0x944c6d0a),
                (0xbb8, 0x285133e7),
                (0xbb8, 0x3f5a56ac),
                (0x5db, 0x951a0818),
            ],
        ),
        (ArchiveVersion::Rar15, None, 20_000, &[(0x278f, 0x07b254b4)]),
        (
            ArchiveVersion::Rar20,
            None,
            3000,
            &[
                (0xbb8, 0x760ca9ab),
                (0xbb8, 0xca11f746),
                (0xbb8, 0xdd1a920d),
                (0x5db, 0x15cd408f),
            ],
        ),
        (ArchiveVersion::Rar20, None, 20_000, &[(0x278f, 0x5b60263c)]),
        (
            ArchiveVersion::Rar29,
            None,
            3000,
            &[
                (0xbb8, 0x94fc7e41),
                (0xbb8, 0xf8469902),
                (0xbb8, 0xdfc9f934),
                (0x5f7, 0xb1b435ec),
            ],
        ),
        (ArchiveVersion::Rar29, None, 20_000, &[(0x2796, 0x29c6b903)]),
        (
            ArchiveVersion::Rar30,
            None,
            3000,
            &[
                (0xbb8, 0xb06e9dcf),
                (0xbb8, 0xdcd47a8c),
                (0xbb8, 0xfb5b1aba),
                (0x5f7, 0xff02d2d9),
            ],
        ),
        (ArchiveVersion::Rar30, None, 20_000, &[(0x2796, 0x2b46b6e7)]),
        (
            ArchiveVersion::Rar40,
            None,
            3000,
            &[
                (0xbb8, 0xb06e9dcf),
                (0xbb8, 0xdcd47a8c),
                (0xbb8, 0xfb5b1aba),
                (0x5f7, 0xff02d2d9),
            ],
        ),
        (ArchiveVersion::Rar40, None, 20_000, &[(0x2796, 0x2b46b6e7)]),
        (
            ArchiveVersion::Rar15,
            Some(b"secret"),
            3000,
            &[
                (0xbb8, 0x1786223f),
                (0xbb8, 0xc41339d9),
                (0xbb8, 0xa1c228e2),
                (0x5db, 0x64e8c6b7),
            ],
        ),
        (
            ArchiveVersion::Rar15,
            Some(b"secret"),
            20_000,
            &[(0x278f, 0xbeba0019)],
        ),
        (
            ArchiveVersion::Rar20,
            Some(b"secret"),
            3000,
            &[
                (0xbb8, 0xbb0b111c),
                (0xbb8, 0x5d314ef1),
                (0xbb8, 0x3c345873),
                (0x5e8, 0x903e5e0f),
            ],
        ),
        (
            ArchiveVersion::Rar20,
            Some(b"secret"),
            20_000,
            &[(0x279c, 0x7bb3e995)],
        ),
    ];
    for (target, password, volume_size, golden) in cases {
        let entry = entry(EntrySource::from_bytes(data()), password);
        let options = WriterOptions::new(target, FeatureSet::store_only());
        let volumes = stream(&entry, options, volume_size).unwrap();
        let got: Vec<(usize, u32)> = volumes
            .iter()
            .map(|volume| (volume.len(), rars::crc32::crc32(volume)))
            .collect();
        assert_eq!(
            got,
            golden,
            "{target:?} password={} size={volume_size}",
            password.is_some()
        );
    }
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
        for target in [ArchiveVersion::Rar30, ArchiveVersion::Rar40] {
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
                volume_number,
                total_volumes,
                ..
            } = event
            {
                self.0.lock().unwrap().push((volume_number, total_volumes));
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
        [(1, Some(4)), (2, Some(4)), (3, Some(4)), (4, Some(4))]
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

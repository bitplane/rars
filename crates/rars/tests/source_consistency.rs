#![cfg(feature = "write")]

use rars::{rar50, ArchiveVersion, EntrySource, FeatureSet, WriterResources};
use std::io::Cursor;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

fn changing_source(len: usize, change_at: usize, changed_len: usize) -> EntrySource {
    let opens = Arc::new(AtomicUsize::new(0));
    EntrySource::from_opener(len as u64, move || {
        let changed = opens.fetch_add(1, Ordering::Relaxed) >= change_at;
        Ok(Box::new(Cursor::new(if changed {
            vec![b'B'; changed_len]
        } else {
            vec![b'A'; len]
        })))
    })
}

fn write_rar50(
    source: EntrySource,
    encrypted: bool,
    volumes: bool,
    level: u8,
) -> rars::Result<Vec<Vec<u8>>> {
    let entry = rar50::ArchiveEntry::new(b"file".to_vec(), source);
    let entry = if encrypted {
        entry.with_password(b"secret".to_vec())
    } else {
        entry
    };
    // Only a BLAKE2sp hash can tell these payloads apart: they share a CRC32.
    let mut features = FeatureSet::default();
    features.blake2sp = true;
    let options =
        rar50::WriterOptions::new(ArchiveVersion::Rar50, features).with_compression_level(level);
    if volumes {
        let mut sink = rar50::CollectedVolumes::new();
        rar50::write_streaming_volumes_to(
            &[entry],
            options,
            rar50::ArchiveExtras::default(),
            1024,
            &mut sink,
            &WriterResources::default(),
        )?;
        Ok(sink.take())
    } else {
        rar50::Rar50Writer::new(options)
            .entry(entry)
            .finish()
            .map(|bytes| vec![bytes])
    }
}

#[test]
fn rar50_stored_emission_rejects_changed_sources() {
    for encrypted in [false, true] {
        for volumes in [false, true] {
            // A member over 256 KiB is copied by a pipeline rather than inline.
            let lens: &[usize] = if volumes { &[4096] } else { &[4096, 1 << 20] };
            for &len in lens {
                for changed_len in [len - 1, len, len + 1] {
                    // A volume set reads a stored member once, hashing it as
                    // it is copied, so what it can catch is a source that is
                    // not the length it declared.
                    let change_at = if volumes { 0 } else { 1 };
                    if volumes && changed_len == len {
                        continue;
                    }
                    let result = write_rar50(
                        changing_source(len, change_at, changed_len),
                        encrypted,
                        volumes,
                        0,
                    );
                    let case = format!(
                        "encrypted={encrypted}, volumes={volumes}, len={len}, size={changed_len}"
                    );
                    let error = result.expect_err(&case);
                    // An encrypted member that runs short still fails as I/O.
                    if !encrypted {
                        assert_eq!(
                            error.kind(),
                            rars::ErrorKind::SourceChanged,
                            "{case}: {error}"
                        );
                    }
                }
            }
        }
    }
}

/// A stored member cut across volumes is read through one open, front to
/// back, so a source that would read differently when opened again still
/// gives each volume bytes from the same read, and the set checks out whole.
#[test]
fn rar50_volume_set_reads_a_stored_member_through_one_open() {
    for encrypted in [false, true] {
        if encrypted && !cfg!(feature = "encryption") {
            continue;
        }
        let volumes = write_rar50(changing_source(4096, 1, 4096), encrypted, true, 0).unwrap();
        assert!(volumes.len() > 3, "{} volumes", volumes.len());
        let password = encrypted.then_some(b"secret".as_slice());
        let archives: Vec<_> = volumes
            .into_iter()
            .map(|bytes| rar50::Archive::parse_owned_with_password(bytes, password).unwrap())
            .collect();
        let options = match password {
            Some(password) => rars::ArchiveReadOptions::with_password(password),
            None => rars::ArchiveReadOptions::new(),
        };
        let extracted = Arc::new(std::sync::Mutex::new(Vec::new()));
        let into = extracted.clone();
        rar50::extract_volumes_to(&archives, options, move |_| {
            Ok(Box::new(Collect(into.clone())))
        })
        .unwrap();
        assert_eq!(*extracted.lock().unwrap(), vec![b'A'; 4096]);
    }
}

struct Collect(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for Collect {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

// Equal-length CRC32 collision, independently constructed with zlib's CRC32.
// Repeating each block preserves the collision for every 1024-byte fragment.
fn crc_collision_payloads() -> (Vec<u8>, Vec<u8>) {
    let original = vec![b'A'; 64];
    let mut changed = vec![b'B'; 60];
    changed.extend_from_slice(&[224, 101, 112, 255]);
    assert_ne!(original, changed);
    assert_eq!(rars::crc32::crc32(&original), 0x414c623c);
    assert_eq!(rars::crc32::crc32(&changed), 0x414c623c);
    let original = original.repeat(64);
    let changed = changed.repeat(64);
    assert_eq!(rars::crc32::crc32(&original), rars::crc32::crc32(&changed));
    (original, changed)
}

#[test]
fn rar50_stored_emission_rejects_crc_collisions_using_the_payload_hash() {
    // A volume set reads a stored member once, so there is no second read to
    // compare with; `rar50_volume_set_reads_a_stored_member_through_one_open`
    // covers it.
    for (encrypted, volumes, change_at) in [(false, false, 1), (true, false, 1)] {
        if encrypted && !cfg!(feature = "encryption") {
            continue;
        }
        let (original, changed) = crc_collision_payloads();
        let opens = Arc::new(AtomicUsize::new(0));
        let source = EntrySource::from_opener(original.len() as u64, move || {
            let data = if opens.fetch_add(1, Ordering::Relaxed) >= change_at {
                changed.clone()
            } else {
                original.clone()
            };
            Ok(Box::new(Cursor::new(data)))
        });
        let error = write_rar50(source, encrypted, volumes, 0).unwrap_err();
        assert_eq!(
            error.kind(),
            rars::ErrorKind::SourceChanged,
            "encrypted={encrypted}, volumes={volumes}, change_at={change_at}: {error}"
        );
        assert_eq!(error.entry_context().unwrap().0, b"file");
        assert!(error.to_string().contains("contents changed"));
    }
}

#[test]
fn rar50_split_member_rejects_a_source_shorter_than_declared() {
    let error = write_rar50(changing_source(4096, 0, 1), false, true, 0).unwrap_err();
    assert_eq!(error.kind(), rars::ErrorKind::SourceChanged);
    assert_eq!(error.entry_context().unwrap().0, b"file");
    assert!(error.to_string().contains("size changed"));
}

#[test]
fn rar50_empty_sources_and_compression_store_fallback_are_verified() {
    for encrypted in [false, true] {
        for volumes in [false, true] {
            // A volume set opens a stored member only to copy it.
            let change_at = if volumes { 0 } else { 1 };
            assert!(write_rar50(changing_source(0, change_at, 1), encrypted, volumes, 0).is_err());
        }
    }
    assert!(write_rar50(changing_source(1, 1, 1), false, false, 3).is_err());
}

#[test]
fn unchanged_rar50_sources_produce_identical_plain_archive_and_volume_bytes() {
    for volumes in [false, true] {
        let expected =
            write_rar50(EntrySource::from_bytes(vec![b'A'; 4096]), false, volumes, 0).unwrap();
        let actual =
            write_rar50(changing_source(4096, usize::MAX, 4096), false, volumes, 0).unwrap();
        assert_eq!(actual, expected);
    }
}

#[test]
#[cfg(feature = "encryption")]
fn unchanged_encrypted_sources_pass_extraction_integrity_checks() {
    for volumes in [false, true] {
        let bytes = write_rar50(changing_source(4096, usize::MAX, 4096), true, volumes, 0).unwrap();
        let archives: Vec<_> = bytes
            .into_iter()
            .map(|bytes| rar50::Archive::parse_owned(bytes).unwrap())
            .collect();
        rar50::extract_volumes_to(
            &archives,
            rars::ArchiveReadOptions::with_password(b"secret"),
            |_| Ok(Box::new(std::io::sink())),
        )
        .unwrap();
    }
}

#[test]
fn legacy_stored_emission_rejects_same_size_content_changes() {
    let resources = WriterResources::default();
    let options13 =
        rars::rar13::WriterOptions::new(ArchiveVersion::Rar14, FeatureSet::store_only());
    let error = rars::rar13::write_streaming_archive_to(
        &[rars::rar13::StreamingEntry::new(
            b"FILE".to_vec(),
            changing_source(4096, 1, 4096),
        )],
        options13,
        rars::MemberCoding::Stored,
        None,
        &resources,
        None,
        &mut Vec::new(),
    )
    .unwrap_err();
    assert!(error.to_string().contains("contents changed"));
    for version in [
        ArchiveVersion::Rar15,
        ArchiveVersion::Rar20,
        ArchiveVersion::Rar29,
    ] {
        let options = rars::rar15_40::WriterOptions::new(version, FeatureSet::store_only());
        let error = rars::rar15_40::write_streaming_archive_to(
            &[rars::rar15_40::StreamingEntry::new(
                b"file".to_vec(),
                changing_source(4096, 1, 4096),
            )],
            options,
            rars::MemberCoding::Stored,
            None,
            &resources,
            None,
            &mut Vec::new(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("contents changed"));
    }
}

#[test]
fn member_io_failures_keep_identity_through_compression_routes() {
    for (level, solid, filter) in [
        (0, false, rar50::FilterPolicy::None),
        (1, false, rar50::FilterPolicy::None),
        (1, true, rar50::FilterPolicy::None),
        (1, false, rar50::FilterPolicy::Auto),
    ] {
        for fail_in_read in [false, true] {
            struct Broken;
            impl std::io::Read for Broken {
                fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "injected read failure",
                    ))
                }
            }
            impl std::io::Seek for Broken {
                fn seek(&mut self, _: std::io::SeekFrom) -> std::io::Result<u64> {
                    Ok(0)
                }
            }
            let mut entries: Vec<_> = (0..8)
                .map(|index| {
                    rar50::ArchiveEntry::new(
                        format!("member-{index}").into_bytes(),
                        EntrySource::from_bytes(vec![b'a'; 128]),
                    )
                })
                .collect();
            entries.push(rar50::ArchiveEntry::new(
                b"failed-member".to_vec(),
                EntrySource::from_opener(128, move || {
                    if fail_in_read {
                        Ok(Box::new(Broken))
                    } else {
                        Err(std::io::Error::new(
                            std::io::ErrorKind::PermissionDenied,
                            "injected open failure",
                        )
                        .into())
                    }
                }),
            ));
            let mut features = FeatureSet::default();
            features.solid = solid;
            let result = rar50::write_streaming_archive_to(
                &entries,
                rar50::WriterOptions::new(ArchiveVersion::Rar50, features)
                    .with_compression_level(level),
                rar50::ArchiveExtras::default().with_filter_policy(filter.clone()),
                &WriterResources::default(),
                &mut Vec::new(),
            );
            let error = result.unwrap_err();
            assert_eq!(error.kind(), rars::ErrorKind::Io);
            assert_eq!(
                error.entry_context(),
                Some((b"failed-member".as_slice(), "compressing"))
            );
            assert!(
                matches!(error.root_cause(), rars::Error::Io(source) if source.kind == std::io::ErrorKind::PermissionDenied)
            );
        }
    }
}

#[test]
fn volume_compression_source_failure_keeps_member_identity() {
    let entry = rar50::ArchiveEntry::new(
        b"failed-member".to_vec(),
        EntrySource::from_opener(128, || {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "injected open failure",
            )
            .into())
        }),
    );
    let mut sink = rar50::CollectedVolumes::new();
    let error = rar50::write_streaming_volumes_to(
        &[entry],
        rar50::WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::default())
            .with_compression_level(1),
        rar50::ArchiveExtras::default(),
        64,
        &mut sink,
        &WriterResources::default(),
    )
    .unwrap_err();
    assert_eq!(error.kind(), rars::ErrorKind::Io);
    assert_eq!(
        error.entry_context(),
        Some((b"failed-member".as_slice(), "compressing"))
    );
    assert!(sink.take().is_empty());
}

#[test]
fn rar50_writer_rejects_aggregate_source_size_overflow_before_reading_or_emitting() {
    for version in [ArchiveVersion::Rar50, ArchiveVersion::Rar70] {
        for volumes in [false, true] {
            let entries: Vec<_> = [(b"huge".as_slice(), u64::MAX), (b"overflow", 1)]
                .into_iter()
                .map(|(name, len)| {
                    rar50::ArchiveEntry::new(
                        name.to_vec(),
                        EntrySource::from_opener(len, || {
                            panic!("overflowing input opened a source")
                        }),
                    )
                })
                .collect();
            let options =
                rar50::WriterOptions::new(version, FeatureSet::default()).with_compression_level(0);
            let mut output = Vec::new();
            let mut sink = rar50::CollectedVolumes::new();
            let error = if volumes {
                rar50::write_streaming_volumes_to(
                    &entries,
                    options,
                    rar50::ArchiveExtras::default(),
                    1024,
                    &mut sink,
                    &WriterResources::default(),
                )
                .unwrap_err()
            } else {
                rar50::write_streaming_archive_to(
                    &entries,
                    options,
                    rar50::ArchiveExtras::default(),
                    &WriterResources::default(),
                    &mut output,
                )
                .unwrap_err()
            };
            assert_eq!(error.kind(), rars::ErrorKind::InvalidArgument);
            assert_eq!(
                error.entry_context().unwrap(),
                (b"overflow".as_slice(), "preparing")
            );
            assert!(error.to_string().contains("total input size overflows"));
            assert!(output.is_empty());
            assert!(sink.take().is_empty());
        }
    }
}

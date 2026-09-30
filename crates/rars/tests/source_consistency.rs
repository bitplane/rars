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
    let options = rar50::WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::default())
        .with_compression_level(level);
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
            for changed_len in [4095, 4096, 4097] {
                let result =
                    write_rar50(changing_source(4096, 1, changed_len), encrypted, volumes, 0);
                assert!(
                    result.is_err(),
                    "encrypted={encrypted}, volumes={volumes}, size={changed_len}"
                );
            }
        }
    }
}

#[test]
fn rar50_fragment_checksums_are_verified_against_the_emission_read() {
    // First open prepares whole-member integrity, second prepares the first
    // fragment's header. Mutation on the third open changes its emitted bytes.
    let error = write_rar50(changing_source(4096, 2, 4096), false, true, 0).unwrap_err();
    assert!(error.to_string().contains("contents changed"));
    assert_eq!(error.kind(), rars::ErrorKind::SourceChanged);
    assert_eq!(error.entry_context().unwrap().0, b"file");
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
    for (encrypted, volumes, change_at) in [
        (false, false, 1),
        (true, false, 1),
        (false, true, 1), // Fragment checksums match the changed bytes; whole-member hash refuses.
        (false, true, 2), // First fragment's CRC matches, but its hash changed after header preparation.
        (true, true, 1), // Encrypted volume staging must verify the source before retaining ciphertext.
    ] {
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
fn rar50_split_header_preparation_rejects_a_truncated_source_reread() {
    let error = write_rar50(changing_source(4096, 1, 1), false, true, 0).unwrap_err();
    assert_eq!(error.kind(), rars::ErrorKind::SourceChanged);
    assert_eq!(error.entry_context().unwrap().0, b"file");
    assert!(error.to_string().contains("size changed"));
}

#[test]
fn rar50_empty_sources_and_compression_store_fallback_are_verified() {
    for encrypted in [false, true] {
        for volumes in [false, true] {
            assert!(write_rar50(changing_source(0, 1, 1), encrypted, volumes, 0).is_err());
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

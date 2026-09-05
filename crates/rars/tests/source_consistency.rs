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

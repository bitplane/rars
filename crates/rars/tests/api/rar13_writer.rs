use super::support::CollectWriter;
use rars::rar13::*;

use rars::atomic64::AtomicU64;
use rars::{
    ArchiveVersion, EntrySource, Error, FeatureSet, MemberCoding, Result, WriteProgress,
    WriteProgressEvent, WriterOption, WriterResources,
};
use std::{
    cell::RefCell,
    rc::Rc,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

#[test]
#[cfg(feature = "encryption")]
fn encrypted_extraction_preserves_output_io_failures() {
    struct FailingWriter;
    impl std::io::Write for FailingWriter {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "closed output",
            ))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let data = b"encrypted output failure".repeat(64);
    let input = [FileEntry {
        name: b"encrypted.bin",
        data: &data,
        file_time: 0,
        file_attr: 0x20,
        password: Some(b"pw"),
        file_comment: None,
    }];
    let bytes = write_compressed_archive(&input, WriterOptions::default()).unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    assert!(archive.entries[0].is_encrypted());
    assert!(!archive.entries[0].is_stored());
    let error = archive
        .extract_to(Some(b"pw"), |_| Ok(Box::new(FailingWriter)))
        .unwrap_err();
    assert_eq!(error.kind(), rars::ErrorKind::Io);
    assert!(error.to_string().contains("closed output"));
}

#[test]
fn compressed_writer_reports_balanced_progress_events() {
    let entries = [
        FileEntry {
            name: b"one.txt",
            data: b"one one one one",
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        },
        FileEntry {
            name: b"two.txt",
            data: b"two two two two",
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        },
    ];
    let operation_starts = AtomicUsize::new(0);
    let operation_finishes = AtomicUsize::new(0);
    let entry_starts = AtomicUsize::new(0);
    let entry_finishes = AtomicUsize::new(0);
    let advances = AtomicUsize::new(0);
    let last_completed = AtomicU64::new(0);
    let expected_total = AtomicU64::new(0);
    let reporter = |event: WriteProgressEvent<'_>| match event {
        WriteProgressEvent::OperationStarted { total_bytes, .. } => {
            operation_starts.fetch_add(1, Ordering::Relaxed);
            expected_total.store(total_bytes.unwrap_or(0), Ordering::Relaxed);
        }
        WriteProgressEvent::OperationFinished { .. } => {
            operation_finishes.fetch_add(1, Ordering::Relaxed);
        }
        WriteProgressEvent::EntryStarted { .. } => {
            entry_starts.fetch_add(1, Ordering::Relaxed);
        }
        WriteProgressEvent::EntryFinished { .. } => {
            entry_finishes.fetch_add(1, Ordering::Relaxed);
        }
        WriteProgressEvent::Advanced {
            completed_bytes,
            total_bytes,
            ..
        } => {
            assert!(completed_bytes >= last_completed.swap(completed_bytes, Ordering::Relaxed));
            assert!(completed_bytes <= total_bytes);
            advances.fetch_add(1, Ordering::Relaxed);
        }
        _ => {}
    };

    write_compressed_archive_with_comment_and_progress(
        &entries,
        WriterOptions::default(),
        None,
        Some(&reporter),
    )
    .unwrap();

    assert_eq!(operation_starts.load(Ordering::Relaxed), 1);
    assert_eq!(operation_finishes.load(Ordering::Relaxed), 1);
    assert_eq!(entry_starts.load(Ordering::Relaxed), entries.len());
    assert_eq!(entry_finishes.load(Ordering::Relaxed), entries.len());
    assert!(advances.load(Ordering::Relaxed) >= entries.len());
    assert_eq!(
        last_completed.load(Ordering::Relaxed),
        expected_total.load(Ordering::Relaxed)
    );
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CollectedEntry {
    name: Vec<u8>,
    data: Vec<u8>,
    file_time: u32,
    file_attr: u8,
    is_directory: bool,
}

fn collect_extract(archive: &Archive, password: Option<&[u8]>) -> Result<Vec<CollectedEntry>> {
    let entries = RefCell::new(Vec::new());
    archive.extract_to(password, |meta| {
        let data = Rc::new(RefCell::new(Vec::new()));
        entries.borrow_mut().push((meta.clone(), Rc::clone(&data)));
        Ok(Box::new(CollectWriter(data)))
    })?;
    Ok(entries
        .into_inner()
        .into_iter()
        .map(|(meta, data)| CollectedEntry {
            name: meta.name,
            data: data.borrow().clone(),
            file_time: meta.file_time,
            file_attr: meta.file_attr,
            is_directory: meta.is_directory,
        })
        .collect())
}

fn collect_extract_volumes(
    volumes: &[Archive],
    password: Option<&[u8]>,
) -> Result<Vec<CollectedEntry>> {
    let entries = RefCell::new(Vec::new());
    extract_volumes_to(volumes, password, |meta| {
        let data = Rc::new(RefCell::new(Vec::new()));
        entries.borrow_mut().push((meta.clone(), Rc::clone(&data)));
        Ok(Box::new(CollectWriter(data)))
    })?;
    Ok(entries
        .into_inner()
        .into_iter()
        .map(|(meta, data)| CollectedEntry {
            name: meta.name,
            data: data.borrow().clone(),
            file_time: meta.file_time,
            file_attr: meta.file_attr,
            is_directory: meta.is_directory,
        })
        .collect())
}

fn synthetic_log_payload(lines: usize) -> Vec<u8> {
    let mut data = Vec::new();
    for index in 0..lines {
        data.extend_from_slice(
            format!(
                "2026-05-12T12:{:02}:{:02}.000Z INFO worker-{:02} request_id={:04x}-{:05} path=/api/v1/items/{} status={} elapsed_ms={} bytes={} message=processed archive chunk retry={} user=service-{}\n",
                index % 60,
                (index * 7) % 60,
                index % 16,
                index % 10000,
                (index * 17) % 100000,
                index % 2048,
                200 + (index % 5),
                (index * 37) % 5000,
                (index * 911) % 65536,
                index % 3,
                index % 32
            )
            .as_bytes(),
        );
    }
    data
}

#[test]
fn writes_and_reads_stored_archive() {
    let input = [
        StoredEntry {
            name: b"README.md",
            data: b"hello rar 1.3",
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        },
        StoredEntry {
            name: b"docs",
            data: b"",
            file_time: 0,
            file_attr: 0x10,
            password: None,
            file_comment: None,
        },
    ];

    let bytes = write_stored_archive(&input, WriterOptions::default()).unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    assert_eq!(archive.main.flags, 0x80);
    assert_eq!(archive.entries.len(), 2);
    assert_eq!(archive.entries[0].name_bytes(), b"README.md");
    assert_eq!(archive.entries[0].name_lossy(), "README.md");
    let extracted = collect_extract(&archive, None).unwrap();
    assert_eq!(extracted[0].data, b"hello rar 1.3");
    assert!(archive.entries[1].is_directory());
    assert!(extracted[1].is_directory);
}

#[test]
fn rejects_truncated_file_payload_during_parse() {
    let input = [StoredEntry {
        name: b"hello.txt",
        data: b"hello",
        file_time: 0,
        file_attr: 0x20,
        password: None,
        file_comment: None,
    }];
    let mut bytes = write_stored_archive(&input, WriterOptions::default()).unwrap();
    bytes.pop();

    assert!(matches!(Archive::parse(&bytes), Err(Error::TooShort)));
}

#[test]
fn returns_none_for_absent_archive_comment() {
    let bytes = write_stored_archive(&[], WriterOptions::default()).unwrap();
    let archive = Archive::parse(&bytes).unwrap();

    assert_eq!(archive.archive_comment().unwrap(), None);
}

#[test]
#[cfg(feature = "encryption")]
fn writes_and_reads_encrypted_stored_archive() {
    let input = [StoredEntry {
        name: b"secret.txt",
        data: b"secret bytes",
        file_time: 0,
        file_attr: 0x20,
        password: Some(b"pass"),
        file_comment: None,
    }];

    let bytes = write_stored_archive(&input, WriterOptions::default()).unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    assert!(archive.entries[0].is_encrypted());
    match collect_extract(&archive, None) {
        Err(Error::NeedPassword) => {}
        Err(Error::AtEntry { source, .. }) if matches!(*source, Error::NeedPassword) => {}
        other => panic!("expected missing password error, got {other:?}"),
    }

    let extracted = collect_extract(&archive, Some(b"pass")).unwrap();
    assert_eq!(extracted[0].data, b"secret bytes");
}

#[test]
fn writes_and_reads_archive_comment() {
    let input = [StoredEntry {
        name: b"README.md",
        data: b"hello rar 1.3",
        file_time: 0,
        file_attr: 0x20,
        password: None,
        file_comment: None,
    }];

    let bytes = write_stored_archive_with_comment(
        &input,
        WriterOptions::default(),
        Some(b"This is an archive comment."),
    )
    .unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    assert!(archive.main.has_archive_comment());
    assert!(archive.main.has_packed_comment());
    assert_eq!(
        archive.archive_comment().unwrap().as_deref(),
        Some(&b"This is an archive comment."[..])
    );
    assert_eq!(
        collect_extract(&archive, None).unwrap()[0].data,
        b"hello rar 1.3"
    );
}

#[test]
fn writes_and_reads_file_comment() {
    let input = [StoredEntry {
        name: b"README.md",
        data: b"hello rar 1.3",
        file_time: 0,
        file_attr: 0x20,
        password: None,
        file_comment: Some(b"file comment\r\n"),
    }];

    let bytes = write_stored_archive(&input, WriterOptions::default()).unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    assert!(archive.entries[0].has_file_comment());
    assert_eq!(
        archive.entries[0].file_comment().unwrap().as_deref(),
        Some(&b"file comment\r\n"[..])
    );
    assert_eq!(
        collect_extract(&archive, None).unwrap()[0].data,
        b"hello rar 1.3"
    );

    let mut truncated_comment = archive.entries[0].clone();
    truncated_comment.extra = vec![5, 0, b'x'];
    assert_eq!(truncated_comment.file_comment(), Err(Error::TooShort));
    assert!(matches!(
        archive.entries[0].verify_checksum(b"wrong data"),
        Err(Error::CrcMismatch { .. })
    ));
}

#[test]
fn compressed_writer_keeps_adaptive_lz_planning_in_sync_after_literals() {
    let data = synthetic_log_payload(8000);
    let input = [FileEntry {
        name: b"synthetic.log",
        data: &data,
        file_time: 0,
        file_attr: 0x20,
        password: None,
        file_comment: None,
    }];

    let bytes =
        write_compressed_archive(&input, WriterOptions::default().with_compression_level(2))
            .unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let extracted = collect_extract(&archive, None).unwrap();

    assert_eq!(extracted[0].data, data);
}

#[test]
fn writes_and_reads_compressed_file_comment() {
    let input = [FileEntry {
        name: b"commented.txt",
        data: b"compressed member with file comment",
        file_time: 0,
        file_attr: 0x20,
        password: None,
        file_comment: Some(b"compressed file comment"),
    }];

    let bytes = write_compressed_archive(&input, WriterOptions::default()).unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    assert_eq!(
        archive.entries[0].file_comment().unwrap().as_deref(),
        Some(&b"compressed file comment"[..])
    );

    let extracted = collect_extract(&archive, None).unwrap();
    assert_eq!(extracted[0].data, input[0].data);
}

#[test]
fn file_checksum_matches_rar13_algorithm() {
    assert_eq!(file_checksum(b""), 0x0000);
    assert_eq!(file_checksum(b"123456789"), 0xc78a);
}

#[test]
fn entry_packed_data_returns_borrowed_slice_for_memory_archives() {
    let payload = b"packed_data direct accessor coverage";
    let input = [StoredEntry {
        name: b"slice.bin",
        data: payload,
        file_time: 0,
        file_attr: 0x20,
        password: None,
        file_comment: None,
    }];

    let bytes = write_stored_archive(&input, WriterOptions::default()).unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let entry = &archive.entries[0];

    let packed = entry.packed_data(&archive).unwrap();
    assert_eq!(packed, payload);
    assert!(!packed.is_empty());
}

#[test]
fn extract_volumes_to_annotates_failed_non_split_entry_with_at_entry() {
    let payload = b"corrupt-me-please";
    let input = [StoredEntry {
        name: b"plain.bin",
        data: payload,
        file_time: 0,
        file_attr: 0x20,
        password: None,
        file_comment: None,
    }];

    let mut bytes = write_stored_archive(&input, WriterOptions::default()).unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let range = archive.entries[0].packed_range.clone();
    // Flip a byte in the stored payload so the checksum no longer matches.
    bytes[range.start] ^= 0xff;

    let corrupted = Archive::parse(&bytes).unwrap();
    let err = collect_extract_volumes(std::slice::from_ref(&corrupted), None).unwrap_err();
    match err {
        Error::AtEntry {
            name,
            operation,
            source,
        } => {
            assert_eq!(name, b"plain.bin");
            assert_eq!(operation, "extracting");
            assert!(matches!(*source, Error::CrcMismatch { .. }));
        }
        other => panic!("expected AtEntry annotation, got {other:?}"),
    }
}

#[test]
fn extract_volumes_to_carries_directory_entries_across_volume_array() {
    // A directory entry has zero-length data and gets the open() callback
    // invoked but no payload write. Putting it in a volumes array keeps
    // the directory branch in extract_volumes_to (rather than extract_to)
    // exercised.
    let input = [StoredEntry {
        name: b"docs",
        data: b"",
        file_time: 0,
        file_attr: 0x10,
        password: None,
        file_comment: None,
    }];
    let bytes = write_stored_archive(&input, WriterOptions::default()).unwrap();
    let archive = Archive::parse(&bytes).unwrap();

    let extracted = collect_extract_volumes(std::slice::from_ref(&archive), None).unwrap();
    assert_eq!(extracted.len(), 1);
    assert!(extracted[0].is_directory);
    assert_eq!(extracted[0].name, b"docs");
}

#[test]
fn write_compressed_archive_with_comment_round_trips_through_archive_comment() {
    let data = b"compressed archive comment payload payload payload";
    let comment = b"This is a compressed archive comment.";
    let input = [FileEntry {
        name: b"payload.txt",
        data,
        file_time: 0,
        file_attr: 0x20,
        password: None,
        file_comment: None,
    }];

    let bytes =
        write_compressed_archive_with_comment(&input, WriterOptions::default(), Some(comment))
            .unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    assert!(archive.main.has_archive_comment());
    assert!(archive.main.has_packed_comment());
    assert_eq!(
        archive.archive_comment().unwrap().as_deref(),
        Some(&comment[..])
    );

    let extracted = collect_extract(&archive, None).unwrap();
    assert_eq!(extracted[0].data, data);
}

#[test]
fn controlled_extraction_uses_selected_directory_and_file_writers() {
    let entries = [
        StoredEntry {
            name: b"docs",
            data: b"",
            file_time: 0,
            file_attr: 0x10,
            password: None,
            file_comment: None,
        },
        StoredEntry {
            name: b"docs/readme.txt",
            data: b"old archive data",
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        },
    ];
    let bytes = write_stored_archive(&entries, WriterOptions::default()).unwrap();
    let archive = rars::Archive::Rar13(Archive::parse(&bytes).unwrap());
    let output = Rc::new(RefCell::new(Vec::new()));
    let mut seen = Vec::new();
    let outcome = archive
        .extract_with_control(rars::ArchiveReadOptions::new(), |member| {
            seen.push(member.meta.name.clone());
            Ok(rars::ExtractionDecision::Extract(Box::new(CollectWriter(
                Rc::clone(&output),
            ))))
        })
        .unwrap();

    assert_eq!(outcome, rars::ExtractionOutcome::Complete);
    assert_eq!(seen, [b"docs".to_vec(), b"docs/readme.txt".to_vec()]);
    assert_eq!(&*output.borrow(), b"old archive data");
}

#[test]
fn streaming_writer_refuses_unsupported_aggregate_quotas_before_output() {
    for (resources, feature) in [
        (
            WriterResources::default().with_max_preparation_bytes(0),
            "preparation memory quota",
        ),
        (
            WriterResources::default().with_max_memory_bytes(0),
            "aggregate managed-memory limit",
        ),
    ] {
        let mut output = Vec::new();
        let error = write_streaming_archive_to(
            &[],
            WriterOptions::default(),
            MemberCoding::Stored,
            None,
            &resources,
            None,
            &mut output,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            Error::UnsupportedFamilyFeature { feature: actual, .. } if actual == feature
        ));
        assert!(output.is_empty());
    }
}

#[test]
fn volume_writer_rejects_empty_payload_for_both_codings() {
    let stored = StoredEntry {
        name: b"empty",
        data: b"",
        file_time: 0,
        file_attr: 0x20,
        password: None,
        file_comment: None,
    };
    let compressed = FileEntry {
        name: stored.name,
        data: stored.data,
        file_time: stored.file_time,
        file_attr: stored.file_attr,
        password: None,
        file_comment: None,
    };
    for error in [
        write_stored_volumes(stored, WriterOptions::default(), 1024).unwrap_err(),
        write_compressed_volumes(compressed, WriterOptions::default(), 1024).unwrap_err(),
    ] {
        assert!(matches!(
            error.root_cause(),
            Error::InvalidArgument("RAR 1.3 volume writer needs a non-empty packed payload")
        ));
    }
}

#[test]
fn write_stored_volumes_rejects_password_protected_entries() {
    let entry = StoredEntry {
        name: b"locked.bin",
        data: b"data",
        file_time: 0,
        file_attr: 0x20,
        password: Some(b"pw"),
        file_comment: None,
    };
    let err = write_stored_volumes(entry, WriterOptions::default(), 16).unwrap_err();
    assert_eq!(
        err,
        Error::UnsupportedWriterOption {
            target: ArchiveVersion::Rar14,
            option: WriterOption::Password,
            because: Some("in a volume set"),
        }
    );
    assert_eq!(
        err.to_string(),
        "encryption is not supported by rar14 (in a volume set)"
    );
}

#[test]
fn write_compressed_volumes_rejects_file_comments() {
    let entry = FileEntry {
        name: b"with-comment.bin",
        data: b"data",
        file_time: 0,
        file_attr: 0x20,
        password: None,
        file_comment: Some(b"note"),
    };
    let err = write_compressed_volumes(entry, WriterOptions::default(), 16).unwrap_err();
    assert_eq!(
        err.to_string(),
        "a per-file comment is not supported by rar14 (in a volume set)"
    );
}

#[test]
fn archive_comment_rejects_size_field_shorter_than_two_bytes() {
    // Build a valid stored archive then patch its main header so the
    // declared comment field is shorter than two bytes — exercises the
    // "packed archive comment is shorter than size field" arm.
    let input = [StoredEntry {
        name: b"file.bin",
        data: b"data",
        file_time: 0,
        file_attr: 0x20,
        password: None,
        file_comment: None,
    }];
    let bytes =
        write_stored_archive_with_comment(&input, WriterOptions::default(), Some(b"hi")).unwrap();
    let mut archive = Archive::parse(&bytes).unwrap();
    // The first two bytes of `main.extra` are the comment_field length —
    // overwrite them with 1 to declare a sub-2-byte payload while keeping
    // the packed-comment flag set.
    archive.main.extra[0] = 1;
    archive.main.extra[1] = 0;
    assert_eq!(
        archive.archive_comment(),
        Err(Error::InvalidHeader(
            "RAR 1.3 packed archive comment is shorter than size field"
        ))
    );
}

#[test]
fn archive_comment_rejects_packed_payload_extending_past_extra_buffer() {
    let input = [StoredEntry {
        name: b"file.bin",
        data: b"data",
        file_time: 0,
        file_attr: 0x20,
        password: None,
        file_comment: None,
    }];
    let bytes =
        write_stored_archive_with_comment(&input, WriterOptions::default(), Some(b"hi")).unwrap();
    let mut archive = Archive::parse(&bytes).unwrap();
    // Pump the declared comment field length up so the packed range walks
    // past the end of `main.extra`.
    let inflated = (archive.main.extra.len() as u16 + 16).to_le_bytes();
    archive.main.extra[0] = inflated[0];
    archive.main.extra[1] = inflated[1];
    assert_eq!(archive.archive_comment(), Err(Error::TooShort));
}

#[test]
fn compression_level_zero_writes_a_stored_member() {
    let entry = FileEntry {
        name: b"ZERO.TXT",
        data: b"zero-level compression leaves these bytes stored",
        file_time: 0,
        file_attr: 0x20,
        password: None,
        file_comment: None,
    };
    let bytes =
        write_compressed_archive(&[entry], WriterOptions::default().with_compression_level(0))
            .unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    assert!(archive.entries[0].is_stored());
    assert_eq!(collect_extract(&archive, None).unwrap()[0].data, entry.data);
}

#[test]
fn stored_volume_writer_refuses_non_legacy_target() {
    let entry = StoredEntry {
        name: b"WRONG.TXT",
        data: b"contents",
        file_time: 0,
        file_attr: 0x20,
        password: None,
        file_comment: None,
    };
    let options = WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only());
    assert_eq!(
        write_stored_volumes(entry, options, 8).unwrap_err(),
        Error::UnsupportedVersion(ArchiveVersion::Rar50)
    );
}

#[test]
fn final_archive_progress_report_can_cancel() {
    struct CancelOnAdvance(AtomicBool);
    impl WriteProgress for CancelOnAdvance {
        fn report(&self, event: WriteProgressEvent<'_>) {
            if matches!(event, WriteProgressEvent::Advanced { .. }) {
                self.0.store(true, Ordering::Relaxed);
            }
        }

        fn is_cancelled(&self) -> bool {
            self.0.load(Ordering::Relaxed)
        }
    }
    let reporter = CancelOnAdvance(AtomicBool::new(false));
    let error = write_streaming_archive_to(
        &[],
        WriterOptions::default(),
        MemberCoding::Stored,
        None,
        &WriterResources::default(),
        Some(&reporter),
        &mut Vec::new(),
    )
    .unwrap_err();
    assert_eq!(error, Error::Cancelled);
}

#[test]
fn volume_extraction_keeps_solid_history_across_regular_members() {
    let entries = [
        FileEntry {
            name: b"FIRST.TXT",
            data: b"first member establishes solid history first member",
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        },
        FileEntry {
            name: b"SECOND.TXT",
            data: b"first member establishes solid history plus a tail",
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        },
    ];
    let mut features = FeatureSet::store_only();
    features.solid = true;
    let bytes = write_compressed_archive(
        &entries,
        WriterOptions::new(ArchiveVersion::Rar14, features),
    )
    .unwrap();
    let archive = Archive::parse(&bytes).unwrap();
    let extracted = collect_extract_volumes(std::slice::from_ref(&archive), None).unwrap();
    assert_eq!(extracted.len(), entries.len());
    for (actual, entry) in extracted.iter().zip(entries) {
        assert_eq!(actual.data, entry.data);
    }
}

#[test]
fn streaming_writer_rejects_directory_payload() {
    let entry = StreamingEntry::new(
        b"directory".to_vec(),
        EntrySource::from_bytes(b"unexpected payload".to_vec()),
    )
    .with_file_attr(0x10);
    let error = write_streaming_archive_to(
        &[entry],
        WriterOptions::default(),
        MemberCoding::Stored,
        None,
        &WriterResources::default(),
        None,
        &mut Vec::new(),
    )
    .unwrap_err();
    assert!(matches!(
        error.root_cause(),
        Error::InvalidArgument("RAR1.3/1.4 directories must have no payload")
    ));
    assert_eq!(
        error.entry_context(),
        Some((&b"directory"[..], "preparing"))
    );
}

fn volume_noise(len: usize, seed: u32) -> Vec<u8> {
    let mut state = seed.wrapping_mul(2_654_435_761) | 1;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect()
}

/// Refuses a set longer than the 901 volumes old-style names reach.
struct NamedSet {
    started: usize,
}

impl VolumeSink for NamedSet {
    fn expect_volumes(&mut self, total: u64) -> Result<()> {
        if total > 901 {
            return Err(Error::InvalidArgument(
                "old-style volume names run out after .z99",
            ));
        }
        Ok(())
    }

    fn start_volume(&mut self, _index: u64) -> Result<Box<dyn VolumeOutput>> {
        self.started += 1;
        Ok(Box::new(std::io::Cursor::new(Vec::new())))
    }
}

#[test]
fn a_set_too_long_to_name_is_refused_before_a_volume_is_written() {
    let entry = StreamingEntry::new(
        b"LONG.BIN".to_vec(),
        EntrySource::from_bytes(volume_noise(64 * 1024, 5)),
    )
    .with_file_attr(0x20);
    // Noise is stored whichever way it is asked for, so both need over
    // a thousand 100-byte volumes.
    for coding in [MemberCoding::Stored, MemberCoding::Compressed] {
        let mut sink = NamedSet { started: 0 };
        let error = write_volumes_to(
            &entry,
            WriterOptions::default(),
            coding.clone(),
            100,
            &mut sink,
            &WriterResources::default(),
            None,
        )
        .unwrap_err();
        assert_eq!(
            error.root_cause(),
            &Error::InvalidArgument("old-style volume names run out after .z99")
        );
        assert_eq!(sink.started, 0, "{coding:?}");
    }
    let mut sink = NamedSet { started: 0 };
    write_volumes_to(
        &entry,
        WriterOptions::default(),
        MemberCoding::Stored,
        1000,
        &mut sink,
        &WriterResources::default(),
        None,
    )
    .unwrap();
    assert!((2..=901).contains(&sink.started), "{}", sink.started);
}

#[test]
fn a_source_that_changes_size_under_a_streamed_set_is_refused() {
    for actual in [4000usize, 4200] {
        let entry = StreamingEntry::new(
            b"MOVING.BIN".to_vec(),
            EntrySource::from_opener(4096, move || {
                Ok(Box::new(std::io::Cursor::new(vec![1u8; actual])))
            }),
        );
        let mut sink = CollectedVolumes::new();
        let error = write_volumes_to(
            &entry,
            WriterOptions::default(),
            MemberCoding::Stored,
            1024,
            &mut sink,
            &WriterResources::default(),
            None,
        )
        .unwrap_err();
        assert!(
            matches!(error.root_cause(), Error::SourceChanged(_)),
            "{actual}: {error:?}"
        );
    }
}

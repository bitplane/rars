use rars::{
    rar13, rar15_40, ArchiveVersion, Builder, EntrySource, Error, ErrorKind, FeatureSet,
    FilterKind, FilterPolicy, MemberCoding, WriteCancellation, WriterResources,
};

#[path = "support/scratch.rs"]
mod scratch;
use std::{
    io::{self, Cursor, Write},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

const FORMATS: [ArchiveVersion; 7] = [
    ArchiveVersion::Rar13,
    ArchiveVersion::Rar14,
    ArchiveVersion::Rar15,
    ArchiveVersion::Rar20,
    ArchiveVersion::Rar29,
    ArchiveVersion::Rar30,
    ArchiveVersion::Rar40,
];

#[test]
fn compressed_legacy_volume_rejects_an_invalid_target_before_encoding() {
    let entry = rar15_40::FileEntry {
        name: b"file",
        data: b"payload",
        file_time: 0,
        file_attr: 0x20,
        host_os: 3,
        password: None,
        file_comment: None,
    };
    let error = rar15_40::write_compressed_volumes(
        entry,
        rar15_40::WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only()),
        1024,
    )
    .unwrap_err();
    assert_eq!(error, Error::UnsupportedVersion(ArchiveVersion::Rar50));
}

#[test]
fn invalid_legacy_compression_level_fails_before_member_io_or_output() {
    let entries = [rar15_40::StreamingEntry::new(
        b"member".to_vec(),
        EntrySource::from_opener(1, || panic!("invalid level opened the source")),
    )];
    let mut output = Vec::new();
    let error = rar15_40::write_streaming_archive_to(
        &entries,
        rar15_40::WriterOptions::new(ArchiveVersion::Rar29, FeatureSet::store_only())
            .with_compression_level(6),
        MemberCoding::Compressed,
        None,
        &WriterResources::default(),
        None,
        &mut output,
    )
    .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::UnsupportedFeature);
    assert!(output.is_empty());
}

#[test]
fn legacy_header_encryption_requires_password_before_member_io_or_output() {
    let entries = [rar15_40::StreamingEntry::new(
        b"member".to_vec(),
        EntrySource::from_opener(1, || panic!("missing password opened member")),
    )];
    let mut features = FeatureSet::store_only();
    features.header_encryption = true;
    let mut output = Vec::new();
    let error = rar15_40::write_streaming_archive_to(
        &entries,
        rar15_40::WriterOptions::new(ArchiveVersion::Rar30, features),
        MemberCoding::Stored,
        None,
        &WriterResources::default(),
        None,
        &mut output,
    )
    .unwrap_err();
    assert!(matches!(error, Error::UnsupportedWriterOption { .. }));
    assert!(output.is_empty());
}

#[test]
fn oversized_legacy_comment_fails_before_opening_member_source() {
    let entries = [rar15_40::StreamingEntry::new(
        b"member".to_vec(),
        EntrySource::from_opener(1, || panic!("oversized comment opened member")),
    )];
    let comment = vec![b'x'; 65536];
    let mut output = Vec::new();
    let error = rar15_40::write_streaming_archive_to(
        &entries,
        rar15_40::WriterOptions::new(ArchiveVersion::Rar15, FeatureSet::store_only()),
        MemberCoding::Stored,
        Some(&comment),
        &WriterResources::default(),
        None,
        &mut output,
    )
    .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidArgument);
    assert!(!output.is_empty());
}

#[test]
fn embedded_comment_that_exceeds_file_header_size_is_rejected() {
    for (comment_len, fits) in [(65486, true), (65487, false)] {
        let mut builder = Builder::new(ArchiveVersion::Rar29).store(true);
        builder
            .add_bytes(b"file".to_vec(), b"payload".to_vec(), None, None)
            .unwrap();
        builder
            .set_file_comment(b"file", Some(vec![b'x'; comment_len]))
            .unwrap();
        if fits {
            let archive = rars::ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
            assert_eq!(archive.read_member(b"file", None).unwrap().unwrap(), b"payload");
        } else {
            let error = builder.to_bytes().unwrap_err();
            assert_eq!(error.kind(), ErrorKind::InvalidArgument);
            assert_eq!(error.entry_context(), Some((b"file".as_slice(), "writing")));
        }
    }
}

#[test]
fn invalid_rar29_filters_fail_before_opening_a_member_or_writing_output() {
    let entries = [rar15_40::StreamingEntry::new(
        b"member".to_vec(),
        EntrySource::from_opener(1, || panic!("invalid filter opened the source")),
    )];
    let options = rar15_40::WriterOptions::new(ArchiveVersion::Rar29, FeatureSet::store_only());
    let cases = [
        (
            FilterKind::Delta { channels: 0 },
            ErrorKind::InvalidArgument,
        ),
        (
            FilterKind::Delta { channels: 33 },
            ErrorKind::InvalidArgument,
        ),
        (
            FilterKind::Audio { channels: 0 },
            ErrorKind::InvalidArgument,
        ),
        (
            FilterKind::Audio { channels: 33 },
            ErrorKind::InvalidArgument,
        ),
        (
            FilterKind::Rgb { width: 0, pos_r: 0 },
            ErrorKind::InvalidArgument,
        ),
        (
            FilterKind::Rgb { width: 4, pos_r: 0 },
            ErrorKind::InvalidArgument,
        ),
        (
            FilterKind::Rgb { width: 3, pos_r: 3 },
            ErrorKind::InvalidArgument,
        ),
        (FilterKind::Arm, ErrorKind::UnsupportedFeature),
    ];
    for (filter, expected) in cases {
        let mut output = Vec::new();
        let error = rar15_40::write_streaming_archive_to(
            &entries,
            options,
            MemberCoding::Filtered(FilterPolicy::explicit(filter)),
            None,
            &WriterResources::default(),
            None,
            &mut output,
        )
        .unwrap_err();
        assert_eq!(error.kind(), expected, "{filter:?}: {error}");
        assert!(output.is_empty(), "{filter:?} wrote archive bytes");
    }

    let mut output = Vec::new();
    let error = rar15_40::write_streaming_archive_to(
        &entries,
        options.with_method(rar15_40::Rar29Method::Ppmd),
        MemberCoding::Filtered(FilterPolicy::Auto),
        None,
        &WriterResources::default(),
        None,
        &mut output,
    )
    .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidArgument);
    assert!(output.is_empty());
}

#[test]
fn rar13_family_rejects_filter_policy_before_member_io_or_output() {
    let entries = [rar13::StreamingEntry::new(
        b"member".to_vec(),
        EntrySource::from_opener(1, || panic!("unsupported filter opened the source")),
    )];
    for format in [ArchiveVersion::Rar13, ArchiveVersion::Rar14] {
        let mut output = Vec::new();
        let error = rar13::write_streaming_archive_to(
            &entries,
            rar13::WriterOptions::new(format, FeatureSet::store_only()),
            MemberCoding::Filtered(FilterPolicy::Auto),
            None,
            &WriterResources::default(),
            None,
            &mut output,
        )
        .unwrap_err();
        assert!(matches!(error, Error::UnsupportedWriterOption { .. }));
        assert!(output.is_empty());
    }
}

#[test]
fn legacy_dictionary_size_is_validated_before_member_io() {
    let entries = [rar15_40::StreamingEntry::new(
        b"member".to_vec(),
        EntrySource::from_opener(1, || panic!("invalid dictionary opened the source")),
    )];
    for size in [0, 96 * 1024, 8 * 1024 * 1024] {
        let mut output = Vec::new();
        let error = rar15_40::write_streaming_archive_to(
            &entries,
            rar15_40::WriterOptions::new(ArchiveVersion::Rar29, FeatureSet::store_only())
                .with_dictionary_size(size),
            MemberCoding::Compressed,
            None,
            &WriterResources::default(),
            None,
            &mut output,
        )
        .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidArgument, "{size}: {error}");
        assert!(output.is_empty());
    }
}

#[test]
fn legacy_resource_limits_fail_before_opening_a_member_or_writing_output() {
    let entries = [rar15_40::StreamingEntry::new(
        b"member".to_vec(),
        EntrySource::from_opener(1, || panic!("unsupported limit opened the source")),
    )];
    let options = rar15_40::WriterOptions::new(ArchiveVersion::Rar29, FeatureSet::store_only());
    for (resources, expected_feature) in [
        (
            WriterResources::default().with_max_preparation_bytes(1),
            "preparation memory quota",
        ),
        (
            WriterResources::default().with_max_memory_bytes(1),
            "aggregate managed-memory limit",
        ),
        (
            WriterResources::default()
                .with_max_preparation_bytes(1)
                .with_max_memory_bytes(1),
            "aggregate managed-memory limit",
        ),
    ] {
        let mut output = Vec::new();
        let error = rar15_40::write_streaming_archive_to(
            &entries,
            options,
            MemberCoding::Stored,
            None,
            &resources,
            None,
            &mut output,
        )
        .unwrap_err();
        assert!(
            matches!(error, Error::UnsupportedFamilyFeature { feature, .. } if feature == expected_feature),
            "{error}"
        );
        assert!(output.is_empty());
    }
}

#[test]
fn legacy_source_length_failure_identifies_the_member_before_output() {
    let root = scratch::case("legacy-missing-source-length");
    let entries = [rar15_40::StreamingEntry::new(
        b"missing".to_vec(),
        EntrySource::from_path(root.join("does-not-exist")),
    )];
    let mut output = Vec::new();
    let error = rar15_40::write_streaming_archive_to(
        &entries,
        rar15_40::WriterOptions::new(ArchiveVersion::Rar29, FeatureSet::store_only()),
        MemberCoding::Stored,
        None,
        &WriterResources::default(),
        None,
        &mut output,
    )
    .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Io);
    assert_eq!(
        error.entry_context(),
        Some((&b"missing"[..], "reading source"))
    );
    assert!(output.is_empty());
}

#[test]
fn legacy_archive_rejects_modern_target_before_encrypted_member_io() {
    let entries = [rar15_40::StreamingEntry::new(
        b"file".to_vec(),
        EntrySource::from_opener(1, || panic!("wrong target opened member")),
    )
    .with_password(b"secret".to_vec())];
    let mut output = Vec::new();
    let error = rar15_40::write_streaming_archive_to(
        &entries,
        rar15_40::WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only()),
        MemberCoding::Stored,
        None,
        &WriterResources::default(),
        None,
        &mut output,
    )
    .unwrap_err();
    assert!(matches!(error, Error::UnsupportedVersion(ArchiveVersion::Rar50)));
    assert!(output.is_empty());
}

#[test]
fn legacy_volume_preflight_rejects_unsupported_options_and_empty_payloads() {
    let entry = rar15_40::StoredEntry {
        name: b"member",
        data: b"payload",
        file_time: 0,
        file_attr: 0x20,
        host_os: 3,
        password: Some(b"password"),
        file_comment: None,
    };
    let plain = rar15_40::WriterOptions::new(ArchiveVersion::Rar30, FeatureSet::store_only());
    let error = rar15_40::write_stored_volumes(
        entry,
        rar15_40::WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only()),
        8,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        Error::UnsupportedVersion(ArchiveVersion::Rar50)
    ));

    let error = rar15_40::write_stored_volumes(
        rar15_40::StoredEntry {
            file_comment: Some(b"comment"),
            ..entry
        },
        plain,
        8,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        Error::UnsupportedFeature {
            feature: "volume_file_comment",
            ..
        }
    ));

    let mut features = FeatureSet::store_only();
    features.header_encryption = true;
    let encrypted = rar15_40::WriterOptions::new(ArchiveVersion::Rar30, features);
    let no_password = rar15_40::StoredEntry {
        password: None,
        ..entry
    };
    assert!(matches!(
        rar15_40::write_stored_volumes(no_password, encrypted, 8),
        Err(Error::UnsupportedWriterOption { .. })
    ));
    assert_eq!(
        rar15_40::write_stored_volumes(entry, encrypted, 0)
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidArgument
    );
    let empty = rar15_40::StoredEntry { data: b"", ..entry };
    assert_eq!(
        rar15_40::write_stored_volumes(empty, plain, 8)
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidArgument
    );
    assert_eq!(
        rar15_40::write_stored_volumes(empty, encrypted, 8)
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidArgument
    );
}

#[test]
fn volume_validation_identifies_members_but_not_global_options() {
    for format in FORMATS {
        for store in [false, true] {
            let mut builder = Builder::new(format).store(store).volume_size(Some(64));
            let name = vec![b'a'; 65536];
            builder
                .add_bytes(name.clone(), b"payload".to_vec(), None, None)
                .unwrap();
            let error = builder.build_volumes(None).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::InvalidArgument);
            assert_eq!(
                error.entry_context(),
                Some((name.as_slice(), "preparing volume member"))
            );

            let mut builder = Builder::new(format).store(store).volume_size(Some(0));
            builder
                .add_bytes(b"file".to_vec(), b"payload".to_vec(), None, None)
                .unwrap();
            let error = builder.build_volumes(None).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::InvalidArgument);
            assert!(error.entry_context().is_none());
        }
    }
}

#[test]
fn encrypted_and_plain_volume_framing_failures_identify_the_member() {
    for encrypted in [false, true] {
        let name = vec![b'a'; 65535];
        let mut builder = Builder::new(ArchiveVersion::Rar30)
            .store(true)
            .volume_size(Some(64));
        if encrypted {
            builder = builder
                .password(Some(b"secret".to_vec()))
                .header_encryption(true);
        }
        builder
            .add_bytes(name.clone(), b"payload".to_vec(), None, None)
            .unwrap();
        let error = builder.build_volumes(None).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidArgument);
        assert_eq!(
            error.entry_context(),
            Some((name.as_slice(), "writing volume member"))
        );
    }
}

fn write(
    format: ArchiveVersion,
    source: EntrySource,
    compressed: bool,
    solid: bool,
    resources: &WriterResources,
    output: &mut dyn Write,
) -> rars::Result<()> {
    let mut features = FeatureSet::store_only();
    features.solid = solid;
    let coding = if compressed {
        MemberCoding::Compressed
    } else {
        MemberCoding::Stored
    };
    if matches!(format, ArchiveVersion::Rar13 | ArchiveVersion::Rar14) {
        let entries = [
            rar13::StreamingEntry::new(
                b"first".to_vec(),
                EntrySource::from_bytes(b"good".to_vec()),
            ),
            rar13::StreamingEntry::new(b"second".to_vec(), source),
        ];
        rar13::write_streaming_archive_to(
            &entries,
            rar13::WriterOptions::new(format, features),
            coding,
            None,
            resources,
            None,
            output,
        )
    } else {
        let entries = [
            rar15_40::StreamingEntry::new(
                b"first".to_vec(),
                EntrySource::from_bytes(b"good".to_vec()),
            ),
            rar15_40::StreamingEntry::new(b"second".to_vec(), source),
        ];
        rar15_40::write_streaming_archive_to(
            &entries,
            rar15_40::WriterOptions::new(format, features),
            coding,
            None,
            resources,
            None,
            output,
        )
    }
}

#[test]
fn source_failures_identify_the_member_in_serial_and_parallel_preparation() {
    for format in FORMATS {
        for (compressed, solid) in [(false, false), (true, false), (true, true)] {
            let source = EntrySource::from_opener(4, || {
                Err(io::Error::new(io::ErrorKind::PermissionDenied, "source denied").into())
            });
            let error = write(
                format,
                source,
                compressed,
                solid,
                &WriterResources::default(),
                &mut Vec::new(),
            )
            .unwrap_err();
            assert_eq!(error.kind(), ErrorKind::Io);
            assert_eq!(error.entry_context(), Some((&b"second"[..], "preparing")));
            assert!(
                matches!(error.root_cause(), Error::Io(io) if io.kind == std::io::ErrorKind::PermissionDenied)
            );
        }
    }
}

#[test]
fn changed_contents_and_lengths_have_the_same_source_changed_category() {
    for format in FORMATS {
        for same_length in [false, true] {
            let opens = Arc::new(AtomicUsize::new(0));
            let source = EntrySource::from_opener(4, move || {
                let data = if opens.fetch_add(1, Ordering::Relaxed) == 0 {
                    b"good".to_vec()
                } else if same_length {
                    b"evil".to_vec()
                } else {
                    b"short".to_vec()
                };
                Ok(Box::new(Cursor::new(data)))
            });
            let error = write(
                format,
                source,
                false,
                false,
                &WriterResources::default(),
                &mut Vec::new(),
            )
            .unwrap_err();
            assert_eq!(error.kind(), ErrorKind::SourceChanged, "{format:?}");
            assert_eq!(error.entry_context(), Some((&b"second"[..], "writing")));
        }
    }
}

#[test]
fn builder_source_materialization_identifies_the_member() {
    for format in FORMATS {
        let mut builder = Builder::new(format);
        builder
            .add_source(
                b"source".to_vec(),
                EntrySource::from_opener(3, || Ok(Box::new(Cursor::new(vec![1])))),
                None,
                None,
            )
            .unwrap();
        let error = builder.to_bytes().unwrap_err();
        assert_eq!(error.kind(), ErrorKind::SourceChanged);
        assert_eq!(
            error.entry_context(),
            Some((&b"source"[..], "reading source"))
        );
    }
}

#[test]
fn member_payload_output_failure_retains_io_kind_and_member() {
    use std::sync::atomic::AtomicBool;
    struct Output(Arc<AtomicBool>);
    impl Write for Output {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.0.load(Ordering::Relaxed) {
                Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "payload sink closed",
                ))
            } else {
                Ok(bytes.len())
            }
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    for format in FORMATS {
        let broken = Arc::new(AtomicBool::new(false));
        let source = EntrySource::from_opener(4, {
            let broken = broken.clone();
            let opens = AtomicUsize::new(0);
            move || {
                if opens.fetch_add(1, Ordering::Relaxed) == 1 {
                    broken.store(true, Ordering::Relaxed);
                }
                Ok(Box::new(Cursor::new(b"good".to_vec())))
            }
        });
        let error = write(
            format,
            source,
            false,
            false,
            &WriterResources::default(),
            &mut Output(broken),
        )
        .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Io);
        assert_eq!(error.entry_context(), Some((&b"second"[..], "writing")));
    }
}

#[test]
fn cancellation_and_shared_output_failures_do_not_blame_a_member() {
    struct BrokenOutput;
    impl Write for BrokenOutput {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    for format in FORMATS {
        let error = write(
            format,
            EntrySource::from_bytes(b"good".to_vec()),
            false,
            false,
            &WriterResources::default(),
            &mut BrokenOutput,
        )
        .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Io);
        assert_eq!(error.entry_context(), None);

        let token = WriteCancellation::new();
        let source = EntrySource::from_opener(4, {
            let token = token.clone();
            move || {
                token.cancel();
                Ok(Box::new(Cursor::new(b"good".to_vec())))
            }
        });
        let error = write(
            format,
            source,
            false,
            false,
            &WriterResources::default().with_cancellation(token),
            &mut Vec::new(),
        )
        .unwrap_err();
        assert_eq!(error, Error::Cancelled);
    }
}

#[test]
fn stored_legacy_emission_propagates_failure_at_every_output_write() {
    struct FailOnWrite {
        fail_at: usize,
        writes: usize,
    }
    impl Write for FailOnWrite {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            let call = self.writes;
            self.writes += 1;
            if call == self.fail_at {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed output"))
            } else {
                Ok(data.len())
            }
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    for format in FORMATS {
        let run = |sink: &mut dyn Write| {
            write(
                format,
                EntrySource::from_bytes(b"good".to_vec()),
                false,
                false,
                &WriterResources::default(),
                sink,
            )
        };
        let mut counting = FailOnWrite {
            fail_at: usize::MAX,
            writes: 0,
        };
        run(&mut counting).unwrap();
        assert!(counting.writes >= 4, "{format:?}");

        let mut member_failure = false;
        let mut archive_failure = false;
        for fail_at in 0..counting.writes {
            let mut sink = FailOnWrite { fail_at, writes: 0 };
            let error = run(&mut sink).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::Io, "{format:?} write {fail_at}");
            assert_eq!(sink.writes, fail_at + 1);
            if error.entry_context().is_some() {
                member_failure = true;
            } else {
                archive_failure = true;
            }
        }
        assert!(member_failure, "{format:?}");
        assert!(archive_failure, "{format:?}");
    }
}

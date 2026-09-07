use rars::{Archive, ArchiveReader, ArchiveVersion, Builder, ErrorKind};

fn mixed(format: ArchiveVersion, solid: bool, stored: bool) -> Archive {
    let mut builder = Builder::new(format).solid(solid).store(stored);
    builder
        .add_directory(b"directory".to_vec(), None, None)
        .unwrap();
    for name in [b"first".as_slice(), b"secret", b"last"] {
        builder
            .add_bytes(name.to_vec(), name.repeat(100), None, None)
            .unwrap();
    }
    builder
        .set_entry_encryption(b"secret", Some(b"password".to_vec()), None)
        .unwrap();
    ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap()
}

#[test]
fn plaintext_selection_ignores_independent_encrypted_members_before_and_after_it() {
    for format in ArchiveVersion::ALL {
        for stored in [false, true] {
            let archive = mixed(format, false, stored);
            for (index, name) in [(1, b"first".as_slice()), (3, b"last")] {
                for password in [None, Some(b"wrong".as_slice())] {
                    assert_eq!(
                        archive.read_member(name, password).unwrap().unwrap(),
                        name.repeat(100),
                        "{format}"
                    );
                    assert_eq!(
                        archive.read_member_at(index, password).unwrap().unwrap(),
                        name.repeat(100),
                        "{format}"
                    );
                }
            }
            assert_eq!(
                archive.read_member(b"secret", None).unwrap_err().kind(),
                ErrorKind::PasswordRequired
            );
            assert_eq!(
                archive.read_member_at(2, None).unwrap_err().kind(),
                ErrorKind::PasswordRequired
            );
            assert_eq!(
                archive
                    .read_member(b"secret", Some(b"password"))
                    .unwrap()
                    .unwrap(),
                b"secret".repeat(100)
            );
            assert!(archive.read_member(b"secret", Some(b"wrong")).is_err());
            assert_eq!(
                archive.test(None).unwrap_err().kind(),
                ErrorKind::PasswordRequired
            );
            assert_eq!(archive.read_member(b"missing", None).unwrap(), None);
            assert_eq!(archive.read_member(b"directory", None).unwrap(), None);
            assert_eq!(archive.read_member_at(0, None).unwrap(), None);
            assert_eq!(archive.read_member_at(10, None).unwrap(), None);
        }
    }
}

#[test]
fn solid_selection_stops_after_target_but_verifies_encrypted_predecessors() {
    for format in ArchiveVersion::ALL {
        let archive = mixed(format, true, false);
        assert_eq!(
            archive.read_member(b"first", None).unwrap().unwrap(),
            b"first".repeat(100)
        );
        assert_eq!(
            archive.read_member_at(1, None).unwrap().unwrap(),
            b"first".repeat(100)
        );
        assert_eq!(
            archive.read_member(b"last", None).unwrap_err().kind(),
            ErrorKind::PasswordRequired
        );
        assert_eq!(
            archive.read_member_at(3, None).unwrap_err().kind(),
            ErrorKind::PasswordRequired
        );
        assert_eq!(
            archive
                .read_member(b"last", Some(b"password"))
                .unwrap()
                .unwrap(),
            b"last".repeat(100)
        );
        assert!(archive.read_member(b"last", Some(b"wrong")).is_err());
    }
}

#[test]
fn selection_preserves_target_integrity_and_last_duplicate_name_identity() {
    for solid in [false, true] {
        let mut builder = Builder::new(ArchiveVersion::Rar29).solid(solid);
        builder
            .add_bytes(b"first".to_vec(), b"first payload".to_vec(), None, None)
            .unwrap();
        builder
            .add_bytes(b"second".to_vec(), b"second payload".to_vec(), None, None)
            .unwrap();
        let mut archive = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
        if let Archive::Rar15To40(legacy) = &mut archive {
            let mut files = legacy.blocks.iter_mut().filter_map(|block| match block {
                rars::rar15_40::Block::File(file) => Some(file),
                _ => None,
            });
            let first = files.next().unwrap();
            first.file_crc ^= 1;
            first.name = b"same".to_vec();
            files.next().unwrap().name = b"same".to_vec();
        }
        assert_eq!(
            archive.read_member_at(0, None).unwrap_err().kind(),
            ErrorKind::ChecksumMismatch
        );
        if solid {
            assert_eq!(
                archive.read_member(b"same", None).unwrap_err().kind(),
                ErrorKind::ChecksumMismatch
            );
        } else {
            assert_eq!(
                archive.read_member(b"same", None).unwrap().unwrap(),
                b"second payload"
            );
            assert_eq!(
                archive.read_member_at(1, None).unwrap().unwrap(),
                b"second payload"
            );
        }
        assert_eq!(
            archive.test(None).unwrap_err().kind(),
            ErrorKind::ChecksumMismatch
        );
    }
}

#[test]
fn option_bearing_reads_apply_budgets_to_selected_payloads_and_solid_dependencies() {
    use rars::ArchiveReadOptions;
    for format in ArchiveVersion::ALL {
        for solid in [false, true] {
            let archive = mixed(format, solid, false);
            let required = if solid { 1500 } else { 400 };
            let options = ArchiveReadOptions::with_password(b"password")
                .with_max_total_output_bytes(required);
            for _ in 0..2 {
                assert_eq!(
                    archive
                        .read_member_with_options(b"last", options)
                        .unwrap()
                        .unwrap(),
                    b"last".repeat(100)
                );
                assert_eq!(
                    archive
                        .read_member_at_with_options(3, options)
                        .unwrap()
                        .unwrap(),
                    b"last".repeat(100)
                );
            }
            let limited = options.with_max_total_output_bytes(required - 1);
            assert!(
                archive.read_member_with_options(b"last", limited).is_err(),
                "{format}, solid={solid}"
            );
            assert_eq!(
                archive
                    .read_member_at_with_options(3, limited)
                    .unwrap_err()
                    .kind(),
                ErrorKind::ResourceLimit
            );
            let member_limit = options.with_max_member_output_bytes(400);
            assert_eq!(
                archive
                    .read_member_with_options(b"last", member_limit)
                    .is_err(),
                solid
            );
            assert!(archive
                .test_with_options(options.with_max_total_output_bytes(1499))
                .is_err());
            archive
                .test_with_options(options.with_max_total_output_bytes(1500))
                .unwrap();
            // Failed policy-bearing calls do not retain policy in the archive.
            archive.test(Some(b"password")).unwrap();
        }
    }
}

#[test]
fn option_bearing_lookup_keeps_duplicate_identity_and_checks_cancellation_before_empty_selection() {
    use rars::{ArchiveReadOptions, ReadCancellation};
    let mut builder = Builder::new(ArchiveVersion::Rar50)
        .store(true)
        .allow_duplicate_names(true);
    builder.add_directory(b"dir".to_vec(), None, None).unwrap();
    builder
        .add_bytes(b"same".to_vec(), b"first".to_vec(), None, None)
        .unwrap();
    builder
        .add_bytes(b"same".to_vec(), b"second".to_vec(), None, None)
        .unwrap();
    builder
        .add_bytes(b"empty".to_vec(), Vec::new(), None, None)
        .unwrap();
    let archive = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
    let options = ArchiveReadOptions::new().with_max_member_output_bytes(5);
    assert_eq!(
        archive
            .read_member_at_with_options(1, options)
            .unwrap()
            .unwrap(),
        b"first"
    );
    assert!(archive.read_member_with_options(b"same", options).is_err());
    let zero = options.with_max_total_output_bytes(0);
    assert_eq!(
        archive.read_member_with_options(b"empty", zero).unwrap(),
        Some(Vec::new())
    );
    assert_eq!(
        archive.read_member_with_options(b"missing", zero).unwrap(),
        None
    );
    assert_eq!(archive.read_member_at_with_options(0, zero).unwrap(), None);
    let token = ReadCancellation::new();
    token.cancel();
    let cancelled = options.with_cancellation(&token);
    for name in [b"same".as_slice(), b"empty", b"missing", b"dir"] {
        assert_eq!(
            archive
                .read_member_with_options(name, cancelled)
                .unwrap_err()
                .kind(),
            ErrorKind::Cancelled
        );
    }
    for index in [0, 1, 3, 99] {
        assert_eq!(
            archive
                .read_member_at_with_options(index, cancelled)
                .unwrap_err()
                .kind(),
            ErrorKind::Cancelled
        );
    }
    assert_eq!(
        archive.test_with_options(cancelled).unwrap_err().kind(),
        ErrorKind::Cancelled
    );
}

#[test]
fn option_bearing_helpers_keep_rar5_dictionary_admission() {
    use rars::ArchiveReadOptions;
    let mut builder = Builder::new(ArchiveVersion::Rar50).compression_level(Some(1));
    builder
        .add_bytes(b"file".to_vec(), b"repeated".repeat(1000), None, None)
        .unwrap();
    let archive = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
    let options = ArchiveReadOptions::new().with_rar50_dictionary_size_limit(0);
    assert_eq!(
        archive
            .read_member_with_options(b"file", options)
            .unwrap_err()
            .kind(),
        ErrorKind::ResourceLimit
    );
    assert_eq!(
        archive
            .read_member_at_with_options(0, options)
            .unwrap_err()
            .kind(),
        ErrorKind::ResourceLimit
    );
    assert_eq!(
        archive.test_with_options(options).unwrap_err().kind(),
        ErrorKind::ResourceLimit
    );
    archive.test(None).unwrap();
}

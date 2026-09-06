use rars::{Archive, ArchiveReader, ArchiveVersion, Builder};

fn archive(size: usize) -> rars::rar50::Archive {
    let mut builder = Builder::new(ArchiveVersion::Rar50).store(true);
    builder
        .add_bytes(b"file".to_vec(), vec![42; size], None, None)
        .unwrap();
    match ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap() {
        Archive::Rar50Plus(a) => a,
        _ => unreachable!(),
    }
}

#[test]
fn unknown_size_flag_does_not_mean_zero_or_the_placeholder_value() {
    for size in [0, 32] {
        let a = archive(size);
        let mut file = a.files().next().unwrap().clone();
        assert_eq!(file.known_unpacked_size(), Some(size as u64));
        file.file_flags |= 0x0008;
        for placeholder in [0, 1, u64::MAX] {
            file.unpacked_size = placeholder;
            assert_eq!(file.known_unpacked_size(), None);
        }
        file.file_flags &= !0x0008;
        assert_eq!(file.known_unpacked_size(), Some(u64::MAX));
    }
}

use rars::{ArchiveReadOptions, Error, ErrorKind};
use std::{cell::RefCell, io::Write, rc::Rc};

struct Capture(Rc<RefCell<Vec<u8>>>);
impl Write for Capture {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.borrow_mut().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn rar5_output_admission_covers_modes_and_preserves_content() {
    for format in [ArchiveVersion::Rar50, ArchiveVersion::Rar70] {
        for (stored, solid) in [(true, false), (false, false), (false, true)] {
            let mut builder = Builder::new(format).store(stored).solid(solid);
            builder
                .add_bytes(b"file".to_vec(), vec![42; 256], None, None)
                .unwrap();
            let archive = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
            for buffered in [0, 1024] {
                for parallel in [false, true] {
                    for limit in [None, Some(256), Some(255), Some(0)] {
                        let mut options =
                            ArchiveReadOptions::new().with_rar50_buffered_decode_limit(buffered);
                        options.max_member_output_bytes = limit;
                        let data = Rc::new(RefCell::new(Vec::new()));
                        let mut opened = 0;
                        let open = |_: &rars::ExtractedEntryMeta| {
                            opened += 1;
                            Ok(Box::new(Capture(data.clone())) as Box<dyn Write>)
                        };
                        let result = if parallel {
                            archive.extract_to_parallel_buffered_with_options(options, open)
                        } else {
                            archive.extract_to_with_options(options, open)
                        };
                        if limit.is_some_and(|limit| limit < 256) {
                            let err = result.unwrap_err();
                            assert_eq!(err.kind(), ErrorKind::ResourceLimit);
                            assert_eq!(err.entry_context().unwrap().0, b"file");
                            assert!(matches!(
                                err.root_cause(),
                                Error::MemberOutputLimitExceeded { required: 256, .. }
                            ));
                            assert_eq!(opened, 0);
                        } else {
                            result.unwrap();
                            assert_eq!(opened, 1);
                            assert_eq!(*data.borrow(), vec![42; 256]);
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn unknown_logical_size_is_refused_only_under_an_output_policy() {
    for size in [0, 32] {
        let mut a = archive(size);
        for b in &mut a.blocks {
            if let rars::rar50::Block::File(f) = b {
                f.file_flags |= 0x8;
            }
        }
        // Characterize existing behavior; the limit does not silently change
        // default extraction to a new decode-to-end implementation.
        a.extract_to(ArchiveReadOptions::new(), |_| Ok(Box::new(std::io::sink())))
            .unwrap();
        for limit in [0, 32, u64::MAX] {
            let err = a
                .extract_to(
                    ArchiveReadOptions::new().with_max_member_output_bytes(limit),
                    |_| panic!("unsupported unknown size opened output"),
                )
                .unwrap_err();
            assert_eq!(err.kind(), ErrorKind::UnsupportedFeature);
        }
    }
}

#[test]
fn split_limit_uses_final_size_and_preserves_early_unknown_placeholders() {
    let mut builder = Builder::new(ArchiveVersion::Rar50)
        .store(true)
        .password(Some(b"secret".to_vec()))
        .volume_size(Some(512));
    builder
        .add_bytes(b"file".to_vec(), vec![42; 2048], None, None)
        .unwrap();
    let mut volumes: Vec<_> = builder
        .build_volumes(None)
        .unwrap()
        .into_iter()
        .map(|b| ArchiveReader::read_owned(b).unwrap())
        .collect();
    assert!(volumes.len() > 1);
    for a in &mut volumes {
        if let Archive::Rar50Plus(a) = a {
            for b in &mut a.blocks {
                if let rars::rar50::Block::File(f) = b {
                    if f.is_split_after() {
                        f.file_flags |= 0x8;
                        f.unpacked_size = u64::MAX;
                    }
                }
            }
        }
    }
    for limit in [2047, 2048] {
        let options =
            ArchiveReadOptions::with_password(b"secret").with_max_member_output_bytes(limit);
        let data = Rc::new(RefCell::new(Vec::new()));
        let mut opened = 0;
        let result = rars::extract_volumes_to_with_options(&volumes, options, |_| {
            opened += 1;
            Ok(Box::new(Capture(data.clone())))
        });
        if limit < 2048 {
            assert_eq!(result.unwrap_err().kind(), ErrorKind::ResourceLimit);
            assert_eq!(opened, 0);
        } else {
            result.unwrap();
            assert_eq!(*data.borrow(), vec![42; 2048]);
        }
    }
    if let Archive::Rar50Plus(a) = volumes.last_mut().unwrap() {
        for b in &mut a.blocks {
            if let rars::rar50::Block::File(f) = b {
                f.file_flags |= 0x8;
            }
        }
    }
    let err = rars::extract_volumes_to_with_options(
        &volumes,
        ArchiveReadOptions::with_password(b"secret").with_max_member_output_bytes(u64::MAX),
        |_| panic!("unknown final size opened output"),
    )
    .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::UnsupportedFeature);
}

#[test]
fn legacy_output_limits_cover_sequential_parallel_and_discarded_solid_members() {
    for format in [
        ArchiveVersion::Rar14,
        ArchiveVersion::Rar15,
        ArchiveVersion::Rar20,
        ArchiveVersion::Rar29,
        ArchiveVersion::Rar30,
        ArchiveVersion::Rar40,
    ] {
        for stored in [true, false] {
            let mut builder = Builder::new(format).store(stored);
            builder
                .add_bytes(b"file".to_vec(), vec![42; 256], None, None)
                .unwrap();
            let archive = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
            for parallel in [false, true] {
                for limit in [255, 256] {
                    let mut opened = 0;
                    let data = Rc::new(RefCell::new(Vec::new()));
                    let open = |_: &rars::ExtractedEntryMeta| {
                        opened += 1;
                        Ok(Box::new(Capture(data.clone())) as Box<dyn Write>)
                    };
                    let options = ArchiveReadOptions::new().with_max_member_output_bytes(limit);
                    let result = if parallel {
                        archive.extract_to_parallel_buffered_with_options(options, open)
                    } else {
                        archive.extract_to_with_options(options, open)
                    };
                    if limit < 256 {
                        assert_eq!(result.unwrap_err().kind(), ErrorKind::ResourceLimit);
                        assert_eq!(opened, 0);
                    } else {
                        result.unwrap();
                        assert_eq!(*data.borrow(), vec![42; 256]);
                    }
                }
            }
        }
    }
    for format in [
        ArchiveVersion::Rar15,
        ArchiveVersion::Rar29,
        ArchiveVersion::Rar50,
    ] {
        let mut builder = Builder::new(format).solid(true);
        builder
            .add_bytes(b"discarded".to_vec(), vec![42; 256], None, None)
            .unwrap();
        builder
            .add_bytes(b"wanted".to_vec(), vec![42; 16], None, None)
            .unwrap();
        let archive = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
        // Discarding output does not exempt a preceding solid member from policy.
        let err = archive
            .extract_to_with_options(
                ArchiveReadOptions::new().with_max_member_output_bytes(16),
                |_| Ok(Box::new(std::io::sink())),
            )
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ResourceLimit);
        assert_eq!(err.entry_context().unwrap().0, b"discarded");
    }
}

#[test]
fn legacy_split_ceiling_applies_to_the_whole_member() {
    for format in [
        ArchiveVersion::Rar14,
        ArchiveVersion::Rar20,
        ArchiveVersion::Rar29,
        ArchiveVersion::Rar40,
    ] {
        let mut builder = Builder::new(format)
            .store(true)
            .password((format != ArchiveVersion::Rar14).then(|| b"secret".to_vec()))
            .volume_size(Some(512));
        builder
            .add_bytes(b"file".to_vec(), vec![42; 2048], None, None)
            .unwrap();
        let volumes: Vec<_> = builder
            .build_volumes(None)
            .unwrap()
            .into_iter()
            .map(|b| ArchiveReader::read_owned(b).unwrap())
            .collect();
        assert!(volumes.len() > 1);
        for limit in [512, 2048] {
            let mut opened = 0;
            let data = Rc::new(RefCell::new(Vec::new()));
            let result = rars::extract_volumes_to_with_options(
                &volumes,
                ArchiveReadOptions::with_password(b"secret").with_max_member_output_bytes(limit),
                |_| {
                    opened += 1;
                    Ok(Box::new(Capture(data.clone())))
                },
            );
            if limit < 2048 {
                assert_eq!(result.unwrap_err().kind(), ErrorKind::ResourceLimit);
                assert_eq!(opened, 0);
            } else {
                result.unwrap();
                assert_eq!(*data.borrow(), vec![42; 2048]);
            }
        }
    }
}

#[test]
fn actual_stored_output_is_guarded_when_legacy_header_understates_size() {
    for encrypted in [false, true] {
        let mut builder = Builder::new(ArchiveVersion::Rar14)
            .store(true)
            .password(encrypted.then(|| b"secret".to_vec()));
        builder
            .add_bytes(b"file".to_vec(), vec![42; 64], None, None)
            .unwrap();
        let mut archive = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
        if let Archive::Rar13(a) = &mut archive {
            a.entries[0].header.unp_size = 16;
        }
        let data = Rc::new(RefCell::new(Vec::new()));
        let mut opened = 0;
        let err = archive
            .extract_to_with_options(
                ArchiveReadOptions::with_password(b"secret").with_max_member_output_bytes(32),
                |_| {
                    opened += 1;
                    Ok(Box::new(Capture(data.clone())))
                },
            )
            .unwrap_err();
        assert_eq!(opened, 1); // Header admission passed, runtime enforcement refused.
        assert!(data.borrow().len() <= 32);
        assert_eq!(err.kind(), ErrorKind::ResourceLimit);
        assert_eq!(err.entry_context().unwrap().0, b"file");
    }
}

#[test]
fn empty_members_and_directories_do_not_consume_output_allowance() {
    for format in [
        ArchiveVersion::Rar14,
        ArchiveVersion::Rar29,
        ArchiveVersion::Rar50,
    ] {
        let mut builder = Builder::new(format).store(true);
        builder
            .add_bytes(b"empty".to_vec(), vec![], None, None)
            .unwrap();
        if format == ArchiveVersion::Rar50 {
            builder.add_directory(b"dir".to_vec(), None, None).unwrap();
        }
        let a = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
        a.extract_to_with_options(
            ArchiveReadOptions::new().with_max_member_output_bytes(0),
            |_| Ok(Box::new(std::io::sink())),
        )
        .unwrap();
    }
}

#[test]
fn split_runtime_guard_and_sink_errors_keep_their_identity() {
    struct Broken;
    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::PermissionDenied.into())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    for format in [
        ArchiveVersion::Rar14,
        ArchiveVersion::Rar29,
        ArchiveVersion::Rar50,
    ] {
        let mut builder = Builder::new(format).store(true).volume_size(Some(512));
        builder
            .add_bytes(b"file".to_vec(), vec![42; 2048], None, None)
            .unwrap();
        let mut volumes: Vec<_> = builder
            .build_volumes(None)
            .unwrap()
            .into_iter()
            .map(|b| ArchiveReader::read_owned(b).unwrap())
            .collect();
        // Deliberately corrupt the final integrity record: a sink refusal must
        // not be replaced with that unrelated checksum diagnostic.
        match volumes.last_mut().unwrap() {
            Archive::Rar13(a) => a.entries.last_mut().unwrap().header.file_crc ^= 1,
            Archive::Rar15To40(a) => {
                for b in &mut a.blocks {
                    if let rars::rar15_40::Block::File(f) = b {
                        f.file_crc ^= 1;
                    }
                }
            }
            Archive::Rar50Plus(a) => {
                for b in &mut a.blocks {
                    if let rars::rar50::Block::File(f) = b {
                        f.data_crc32 = Some(0);
                        f.hash = None;
                    }
                }
            }
            _ => unreachable!(),
        }
        let err = rars::extract_volumes_to_with_options(
            &volumes,
            ArchiveReadOptions::new().with_max_member_output_bytes(2048),
            |_| Ok(Box::new(Broken)),
        )
        .unwrap_err();
        assert!(
            matches!(err.root_cause(), Error::Io(e) if e.kind == std::io::ErrorKind::PermissionDenied)
        );
        // These stored families copy chained data even if the final header lies.
        if format != ArchiveVersion::Rar29 {
            match volumes.last_mut().unwrap() {
                Archive::Rar13(a) => a.entries.last_mut().unwrap().header.unp_size = 16,
                Archive::Rar50Plus(a) => {
                    for b in &mut a.blocks {
                        if let rars::rar50::Block::File(f) = b {
                            f.unpacked_size = 16;
                        }
                    }
                }
                _ => unreachable!(),
            }
            let data = Rc::new(RefCell::new(Vec::new()));
            let err = rars::extract_volumes_to_with_options(
                &volumes,
                ArchiveReadOptions::new().with_max_member_output_bytes(512),
                |_| Ok(Box::new(Capture(data.clone()))),
            )
            .unwrap_err();
            assert_eq!(err.kind(), ErrorKind::ResourceLimit);
            assert!(data.borrow().len() <= 512);
        }
    }
}

#[test]
fn filtered_output_is_counted_once_and_limits_remain_distinct() {
    let a = ArchiveReader::read(include_bytes!("fixtures/rar50/filter_delta.rar")).unwrap();
    let expected = Rc::new(RefCell::new(Vec::new()));
    a.extract_to(None, |_| Ok(Box::new(Capture(expected.clone()))))
        .unwrap();
    let size = expected.borrow().len() as u64;
    assert!(size > 0);
    let actual = Rc::new(RefCell::new(Vec::new()));
    a.extract_to_with_options(
        ArchiveReadOptions::new().with_max_member_output_bytes(size),
        |_| Ok(Box::new(Capture(actual.clone()))),
    )
    .unwrap();
    assert_eq!(*actual.borrow(), *expected.borrow());
    let err = a
        .extract_to_with_options(
            ArchiveReadOptions::new().with_max_member_output_bytes(size - 1),
            |_| panic!("oversized filtered member opened output"),
        )
        .unwrap_err();
    assert!(matches!(
        err.root_cause(),
        Error::MemberOutputLimitExceeded { .. }
    ));
    let err = a
        .extract_to_with_options(
            ArchiveReadOptions::new()
                .with_max_member_output_bytes(size)
                .with_rar50_buffered_decode_limit(0),
            |_| Ok(Box::new(std::io::sink())),
        )
        .unwrap_err();
    assert!(matches!(
        err.root_cause(),
        Error::Rar50BufferedDecodeLimitExceeded { .. }
    ));
}

#[test]
fn allowance_resets_between_members_including_solid_and_parallel_paths() {
    for format in [
        ArchiveVersion::Rar14,
        ArchiveVersion::Rar29,
        ArchiveVersion::Rar50,
    ] {
        for solid in [false, true] {
            let mut builder = Builder::new(format).solid(solid);
            for name in [b"first".as_slice(), b"second".as_slice()] {
                builder
                    .add_bytes(name.to_vec(), vec![42; 32], None, None)
                    .unwrap();
            }
            let a = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
            for parallel in [false, true] {
                let data = Rc::new(RefCell::new(Vec::new()));
                let open = |_: &rars::ExtractedEntryMeta| {
                    Ok(Box::new(Capture(data.clone())) as Box<dyn Write>)
                };
                let options = ArchiveReadOptions::new().with_max_member_output_bytes(32);
                if parallel {
                    a.extract_to_parallel_buffered_with_options(options, open)
                        .unwrap();
                } else {
                    a.extract_to_with_options(options, open).unwrap();
                }
                assert_eq!(*data.borrow(), vec![42; 64]);
            }
        }
    }
}

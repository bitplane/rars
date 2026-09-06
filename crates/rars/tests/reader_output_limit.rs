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
                        options.rar50_max_member_output_bytes = limit;
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
                    ArchiveReadOptions::new().with_rar50_max_member_output_bytes(limit),
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
            ArchiveReadOptions::with_password(b"secret").with_rar50_max_member_output_bytes(limit);
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
        ArchiveReadOptions::with_password(b"secret").with_rar50_max_member_output_bytes(u64::MAX),
        |_| panic!("unknown final size opened output"),
    )
    .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::UnsupportedFeature);
}

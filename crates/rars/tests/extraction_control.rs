use rars::{
    Archive, ArchiveReadOptions, ArchiveReader, ArchiveVersion, Builder, Error,
    ExtractionDecision as Decision, ExtractionOutcome as Outcome,
};
use std::{cell::RefCell, io, io::Write, rc::Rc};

const VERSIONS: [ArchiveVersion; 8] = [
    ArchiveVersion::Rar14,
    ArchiveVersion::Rar15,
    ArchiveVersion::Rar20,
    ArchiveVersion::Rar29,
    ArchiveVersion::Rar30,
    ArchiveVersion::Rar40,
    ArchiveVersion::Rar50,
    ArchiveVersion::Rar70,
];

struct Capture(Rc<RefCell<Vec<u8>>>);
impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.borrow_mut().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn archive(version: ArchiveVersion, solid: bool, encrypted: bool) -> Archive {
    let mut builder = Builder::new(version)
        .solid(solid)
        .password(encrypted.then(|| b"secret".to_vec()));
    for (name, len) in [(b"first".as_slice(), 4096), (b"second", 32), (b"third", 64)] {
        builder
            .add_bytes(name.to_vec(), vec![42; len], None, None)
            .unwrap();
    }
    ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap()
}

#[test]
fn skip_precedes_limits_and_stop_precedes_later_members() {
    for version in VERSIONS {
        let archive = archive(version, false, false);
        let output = Rc::new(RefCell::new(Vec::new()));
        let mut visited = Vec::new();
        let outcome = archive
            .extract_with_control(
                ArchiveReadOptions::new()
                    .with_max_member_output_bytes(32)
                    .with_max_total_output_bytes(32),
                |member| {
                    visited.push(member.meta.name.clone());
                    Ok(match member.meta.name.as_slice() {
                        b"first" => {
                            assert_eq!(member.meta.unpacked_size, 4096);
                            Decision::Skip
                        }
                        b"second" => Decision::Extract(Box::new(Capture(output.clone()))),
                        _ => Decision::Stop,
                    })
                },
            )
            .unwrap();
        assert_eq!(outcome, Outcome::Stopped);
        assert_eq!(*output.borrow(), vec![42; 32]);
        assert_eq!(
            visited,
            [b"first".to_vec(), b"second".to_vec(), b"third".to_vec()]
        );
        let mut calls = 0;
        assert_eq!(
            archive
                .extract_with_control(ArchiveReadOptions::new(), |_| {
                    calls += 1;
                    Ok(Decision::Stop)
                })
                .unwrap(),
            Outcome::Stopped
        );
        assert_eq!(calls, 1);
    }
}

#[test]
fn encrypted_members_can_be_skipped_without_a_password() {
    for version in VERSIONS.into_iter().filter(|v| *v != ArchiveVersion::Rar14) {
        let archive = archive(version, false, true);
        let mut calls = 0;
        let outcome = archive
            .extract_with_control(ArchiveReadOptions::new(), |member| {
                assert!(member.meta.is_encrypted);
                calls += 1;
                Ok(Decision::Skip)
            })
            .unwrap();
        assert_eq!(outcome, Outcome::Complete);
        assert_eq!(calls, 3);
    }
}

#[test]
fn solid_skipping_is_refused_but_discarding_preserves_history_and_accounting() {
    for version in VERSIONS {
        let archive = archive(version, true, false);
        let error = archive
            .extract_with_control(ArchiveReadOptions::new(), |_| Ok(Decision::Skip))
            .unwrap_err();
        assert!(matches!(error.root_cause(), Error::CannotSkipSolidMember));
        assert_eq!(error.entry_context().unwrap().0, b"first");
        let output = Rc::new(RefCell::new(Vec::new()));
        assert_eq!(
            archive
                .extract_with_control(ArchiveReadOptions::new(), |member| {
                    Ok(Decision::Extract(if member.meta.name == b"first" {
                        Box::new(io::sink()) as Box<dyn Write>
                    } else {
                        Box::new(Capture(output.clone()))
                    }))
                })
                .unwrap(),
            Outcome::Complete
        );
        assert_eq!(*output.borrow(), vec![42; 96]);
        let error = archive
            .extract_with_control(
                ArchiveReadOptions::new().with_max_total_output_bytes(4096),
                |_| Ok(Decision::Extract(Box::new(io::sink()))),
            )
            .unwrap_err();
        assert_eq!(error.kind(), rars::ErrorKind::ResourceLimit);
        assert_eq!(error.entry_context().unwrap().0, b"second");
    }
}

#[test]
fn callback_cancellation_and_errors_do_not_become_successful_stops() {
    let archive = archive(ArchiveVersion::Rar50, false, false);
    let token = rars::ReadCancellation::new();
    let error = archive
        .extract_with_control(ArchiveReadOptions::new().with_cancellation(&token), |_| {
            token.cancel();
            Ok(Decision::Stop)
        })
        .unwrap_err();
    assert_eq!(error.kind(), rars::ErrorKind::Cancelled);
    let mut calls = 0;
    let error = archive
        .extract_with_control(ArchiveReadOptions::new(), |_| {
            calls += 1;
            Err(io::Error::from(io::ErrorKind::PermissionDenied).into())
        })
        .unwrap_err();
    assert_eq!(error.kind(), rars::ErrorKind::Io);
    assert_eq!(calls, 1);
}

#[test]
fn skipping_a_bad_checksum_continues_but_extracting_it_stops() {
    for version in [
        ArchiveVersion::Rar14,
        ArchiveVersion::Rar29,
        ArchiveVersion::Rar50,
    ] {
        let mut archive = archive(version, false, false);
        match &mut archive {
            Archive::Rar13(a) => a.entries[0].header.file_crc ^= 1,
            Archive::Rar15To40(a) => {
                for block in &mut a.blocks {
                    if let rars::rar15_40::Block::File(file) = block {
                        if file.name == b"first" {
                            file.file_crc ^= 1;
                        }
                    }
                }
            }
            Archive::Rar50Plus(a) => {
                for block in &mut a.blocks {
                    if let rars::rar50::Block::File(file) = block {
                        if file.name == b"first" {
                            file.hash = None;
                            file.data_crc32 = Some(file.data_crc32.unwrap() ^ 1);
                        }
                    }
                }
            }
            _ => unreachable!(),
        }
        let output = Rc::new(RefCell::new(Vec::new()));
        assert_eq!(
            archive
                .extract_with_control(ArchiveReadOptions::new(), |member| {
                    Ok(if member.meta.name == b"first" {
                        Decision::Skip
                    } else {
                        Decision::Extract(Box::new(Capture(output.clone())))
                    })
                })
                .unwrap(),
            Outcome::Complete
        );
        assert_eq!(*output.borrow(), vec![42; 96]);
        let mut calls = 0;
        let error = archive
            .extract_with_control(ArchiveReadOptions::new(), |_| {
                calls += 1;
                Ok(Decision::Extract(Box::new(io::sink())))
            })
            .unwrap_err();
        assert_eq!(error.kind(), rars::ErrorKind::ChecksumMismatch);
        assert_eq!(calls, 1);

        for limit in [4096, 4192] {
            let output = Rc::new(RefCell::new(Vec::new()));
            let mut failures = 0;
            let result = archive.extract_with_control_and_errors(
                ArchiveReadOptions::new()
                    .with_max_total_output_bytes(limit)
                    .with_rar50_buffered_decode_limit(0),
                |member| {
                    Ok(Decision::Extract(if member.meta.name == b"first" {
                        Box::new(io::sink()) as Box<dyn Write>
                    } else {
                        Box::new(Capture(output.clone()))
                    }))
                },
                |member, error| {
                    assert_eq!(member.meta.name, b"first");
                    assert_eq!(error.kind(), rars::ErrorKind::ChecksumMismatch);
                    failures += 1;
                    Ok(rars::ExtractionErrorAction::Continue)
                },
            );
            assert_eq!(failures, 1);
            if limit == 4096 {
                let error = result.unwrap_err();
                assert_eq!(error.kind(), rars::ErrorKind::ResourceLimit);
                assert_eq!(error.entry_context().unwrap().0, b"second");
                assert!(output.borrow().is_empty());
            } else {
                assert_eq!(result.unwrap(), Outcome::Complete);
                assert_eq!(*output.borrow(), vec![42; 96]);
            }
        }
    }
}

#[test]
fn solid_failures_and_callback_errors_cannot_be_continued() {
    struct Broken;
    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::ErrorKind::PermissionDenied.into())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    for version in VERSIONS {
        let archive = archive(version, true, false);
        let error = archive
            .extract_with_control_and_errors(
                ArchiveReadOptions::new(),
                |_| Ok(Decision::Extract(Box::new(Broken))),
                |_, _| panic!("solid failure must not offer recovery"),
            )
            .unwrap_err();
        assert_eq!(error.kind(), rars::ErrorKind::Io);
    }
    let archive = archive(ArchiveVersion::Rar50, false, false);
    let error = archive
        .extract_with_control_and_errors(
            ArchiveReadOptions::new(),
            |_| Err(io::Error::other("callback failed").into()),
            |_, _| panic!("decision callback errors are fatal"),
        )
        .unwrap_err();
    assert_eq!(error.kind(), rars::ErrorKind::Io);
}

#[test]
fn skip_and_stop_do_not_read_payloads_from_a_caller_source() {
    use std::io::{Cursor, Read, Seek, SeekFrom};
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    struct Source(Cursor<Vec<u8>>, Arc<AtomicBool>);
    impl Read for Source {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            if self.1.load(Ordering::Relaxed) {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            self.0.read(bytes)
        }
    }
    impl Seek for Source {
        fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
            self.0.seek(from)
        }
    }
    for version in [
        ArchiveVersion::Rar14,
        ArchiveVersion::Rar29,
        ArchiveVersion::Rar50,
    ] {
        let mut builder = Builder::new(version).store(true);
        builder
            .add_bytes(b"file".to_vec(), vec![42; 1024], None, None)
            .unwrap();
        let fail = Arc::new(AtomicBool::new(false));
        let archive = ArchiveReader::read_reader(Source(
            Cursor::new(builder.to_bytes().unwrap()),
            fail.clone(),
        ))
        .unwrap();
        fail.store(true, Ordering::Relaxed);
        assert_eq!(
            archive
                .extract_with_control(ArchiveReadOptions::new(), |_| Ok(Decision::Skip))
                .unwrap(),
            Outcome::Complete
        );
        assert_eq!(
            archive
                .extract_with_control(ArchiveReadOptions::new(), |_| Ok(Decision::Stop))
                .unwrap(),
            Outcome::Stopped
        );
    }
}

use rars::{Archive, ArchiveReadOptions, ArchiveReader, ArchiveVersion, Builder, ErrorKind};
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct Fault {
    operations: usize,
    fail_at: Option<usize>,
}
impl Fault {
    fn check(&mut self) -> io::Result<()> {
        self.operations += 1;
        if self.fail_at == Some(self.operations) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "injected source failure",
            ));
        }
        Ok(())
    }
    fn arm(&mut self, fail_at: Option<usize>) {
        self.operations = 0;
        self.fail_at = fail_at;
    }
}
struct Source {
    bytes: Cursor<Vec<u8>>,
    fault: Arc<Mutex<Fault>>,
}
impl Read for Source {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.fault.lock().unwrap().check()?;
        let count = bytes.len().min(17);
        self.bytes.read(&mut bytes[..count])
    }
}
impl Seek for Source {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        self.fault.lock().unwrap().check()?;
        self.bytes.seek(from)
    }
}
fn images() -> Vec<(ArchiveVersion, bool, Vec<u8>)> {
    let mut cases = Vec::new();
    for version in [
        ArchiveVersion::Rar13,
        ArchiveVersion::Rar14,
        ArchiveVersion::Rar15,
        ArchiveVersion::Rar20,
        ArchiveVersion::Rar30,
        ArchiveVersion::Rar50,
        ArchiveVersion::Rar70,
    ] {
        for stored in [false, true] {
            for encrypted in [false, true] {
                if encrypted && matches!(version, ArchiveVersion::Rar13 | ArchiveVersion::Rar14) {
                    continue;
                }
                let mut builder = Builder::new(version)
                    .compression_level(Some(if stored { 0 } else { 1 }))
                    .password(encrypted.then(|| b"secret".to_vec()));
                builder
                    .add_bytes(
                        b"payload".to_vec(),
                        b"repeatable member payload\n".repeat(16),
                        None,
                        None,
                    )
                    .unwrap();
                cases.push((version, encrypted, builder.to_bytes().unwrap()));
            }
        }
    }
    cases
}
fn parse(
    bytes: &[u8],
    fault: &Arc<Mutex<Fault>>,
    options: ArchiveReadOptions<'_>,
) -> rars::Result<Archive> {
    ArchiveReader::read_reader_with_options(
        Source {
            bytes: Cursor::new(bytes.to_vec()),
            fault: fault.clone(),
        },
        options,
    )
}

#[test]
fn every_seekable_parser_source_failure_is_reported_without_a_partial_archive() {
    for (version, encrypted, bytes) in images() {
        let options =
            ArchiveReadOptions::with_optional_password(encrypted.then_some(b"secret".as_slice()));
        let fault = Arc::new(Mutex::new(Fault::default()));
        parse(&bytes, &fault, options).unwrap();
        let operations = fault.lock().unwrap().operations;
        assert!(operations > 0);
        for fail_at in 1..=operations {
            fault.lock().unwrap().arm(Some(fail_at));
            let error = parse(&bytes, &fault, options).unwrap_err();
            assert_eq!(
                error.kind(),
                ErrorKind::Io,
                "{version:?}, encrypted {encrypted}, operation {fail_at}: {error}"
            );
            assert!(error.to_string().contains("injected source failure"));
        }
    }
}

struct Capture(Arc<Mutex<Vec<u8>>>);
impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
#[test]
fn source_failures_abort_member_publication_and_the_archive_can_be_retried() {
    let expected = b"repeatable member payload\n".repeat(16);
    for (version, encrypted, bytes) in images() {
        for streaming in [false, true] {
            let mut options = ArchiveReadOptions::with_optional_password(
                encrypted.then_some(b"secret".as_slice()),
            );
            if streaming {
                options = options.with_rar50_buffered_decode_limit(0);
            }
            let fault = Arc::new(Mutex::new(Fault::default()));
            let archive = parse(&bytes, &fault, options).unwrap();
            let output = Arc::new(Mutex::new(Vec::new()));
            fault.lock().unwrap().arm(None);
            archive
                .extract_to_with_options(options, |_| Ok(Box::new(Capture(output.clone()))))
                .unwrap();
            assert_eq!(*output.lock().unwrap(), expected);
            let operations = fault.lock().unwrap().operations;
            for fail_at in 1..=operations {
                output.lock().unwrap().clear();
                fault.lock().unwrap().arm(Some(fail_at));
                let error = archive
                    .extract_to_with_options(options, |_| Ok(Box::new(Capture(output.clone()))))
                    .unwrap_err();
                assert!(
                    matches!(error.kind(), ErrorKind::Io),
                    "{version:?}, streaming {streaming}, operation {fail_at}: {error}"
                );
                assert!(error.to_string().contains("injected source failure"));
                assert_eq!(
                    error.entry_context().map(|(name, _)| name),
                    Some(b"payload".as_slice()),
                    "{version:?}, encrypted {encrypted}, streaming {streaming}, operation {fail_at}: {error}"
                );
                let output = output.lock().unwrap();
                assert!(
                    expected.starts_with(&output),
                    "failure must leave only a correct prefix"
                );
            }
            output.lock().unwrap().clear();
            fault.lock().unwrap().arm(None);
            archive
                .extract_to_with_options(options, |_| Ok(Box::new(Capture(output.clone()))))
                .unwrap();
            assert_eq!(*output.lock().unwrap(), expected);
        }
    }
}

struct FailingSink;
impl Write for FailingSink {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "injected sink failure",
        ))
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
#[test]
fn sink_failures_preserve_io_identity_and_member_context() {
    for (version, encrypted, bytes) in images() {
        for streaming in [false, true] {
            let mut options = ArchiveReadOptions::with_optional_password(
                encrypted.then_some(b"secret".as_slice()),
            );
            if streaming {
                options = options.with_rar50_buffered_decode_limit(0);
            }
            let fault = Arc::new(Mutex::new(Fault::default()));
            let archive = parse(&bytes, &fault, options).unwrap();
            let error = archive
                .extract_to_with_options(options, |_| Ok(Box::new(FailingSink)))
                .unwrap_err();
            assert_eq!(error.kind(), ErrorKind::Io, "{version:?}: {error}");
            assert_eq!(
                error.entry_context().map(|(name, _)| name),
                Some(b"payload".as_slice())
            );
            assert!(error.to_string().contains("injected sink failure"));
            let rars::Error::Io(source) = error.root_cause() else {
                panic!("{error}")
            };
            let original = source.source().downcast_ref::<io::Error>().unwrap();
            assert_eq!(original.kind(), io::ErrorKind::PermissionDenied);
        }
    }
}

#[test]
fn split_and_parallel_sink_failures_keep_member_context() {
    for version in [
        ArchiveVersion::Rar15,
        ArchiveVersion::Rar20,
        ArchiveVersion::Rar30,
        ArchiveVersion::Rar50,
    ] {
        for stored in [false, true] {
            let mut builder = Builder::new(version)
                .compression_level(Some(if stored { 0 } else { 1 }))
                .volume_size(Some(512));
            // Poorly compressible bytes force genuine multiple volumes.
            let mut state = 0x12345678u32;
            let payload: Vec<u8> = (0..16384)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 17;
                    state ^= state << 5;
                    state as u8
                })
                .collect();
            builder
                .add_bytes(b"payload".to_vec(), payload, None, None)
                .unwrap();
            let mut volumes: Vec<_> = builder
                .build_volumes(None)
                .unwrap()
                .into_iter()
                .map(|b| ArchiveReader::read_owned(b).unwrap())
                .collect();
            assert!(volumes.len() > 1, "{version:?}, stored={stored}");
            let error = rars::extract_volumes_to_with_options(
                &volumes,
                ArchiveReadOptions::default(),
                |_| Ok(Box::new(FailingSink)),
            )
            .unwrap_err();
            assert_eq!(error.kind(), ErrorKind::Io, "{version:?}: {error}");
            assert_eq!(
                error.entry_context().map(|(name, _)| name),
                Some(b"payload".as_slice())
            );
            assert!(error.to_string().contains("injected sink failure"));
            // A separately corrupted final integrity record must still name
            // the logical split member after all fragments have been decoded.
            if let Archive::Rar15To40(last) = volumes.last_mut().unwrap() {
                for block in &mut last.blocks {
                    if let rars::rar15_40::Block::File(file) = block {
                        file.file_crc ^= 1;
                    }
                }
                let error = rars::extract_volumes_to_with_options(
                    &volumes,
                    ArchiveReadOptions::default(),
                    |_| Ok(Box::new(io::sink())),
                )
                .unwrap_err();
                assert_eq!(error.kind(), ErrorKind::ChecksumMismatch);
                assert_eq!(
                    error.entry_context().map(|(name, _)| name),
                    Some(b"payload".as_slice())
                );
            }
        }
    }
    for (_, encrypted, bytes) in images() {
        let options =
            ArchiveReadOptions::with_optional_password(encrypted.then_some(b"secret".as_slice()));
        let archive = ArchiveReader::read_owned_with_options(bytes, options).unwrap();
        let error = archive
            .extract_to_parallel_buffered_with_options(options, |_| Ok(Box::new(FailingSink)))
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Io);
        assert_eq!(
            error.entry_context().map(|(name, _)| name),
            Some(b"payload".as_slice())
        );
    }
}

#[test]
fn encrypted_header_source_failures_remain_io_errors() {
    for version in [ArchiveVersion::Rar30, ArchiveVersion::Rar50] {
        let mut builder = Builder::new(version)
            .password(Some(b"secret".to_vec()))
            .header_encryption(true);
        builder
            .add_bytes(b"payload".to_vec(), b"data".to_vec(), None, None)
            .unwrap();
        let bytes = builder.to_bytes().unwrap();
        let options = ArchiveReadOptions::with_password(b"secret");
        let fault = Arc::new(Mutex::new(Fault::default()));
        parse(&bytes, &fault, options).unwrap();
        let operations = fault.lock().unwrap().operations;
        for fail_at in 1..=operations {
            fault.lock().unwrap().arm(Some(fail_at));
            let error = parse(&bytes, &fault, options).unwrap_err();
            assert_eq!(
                error.kind(),
                ErrorKind::Io,
                "{version:?}, operation {fail_at}: {error}"
            );
            assert!(error.to_string().contains("injected source failure"));
        }
    }
}

#[test]
fn parallel_stored_source_failure_retains_member_context() {
    for version in [ArchiveVersion::Rar15, ArchiveVersion::Rar50] {
        let mut builder = Builder::new(version).store(true);
        builder
            .add_bytes(b"payload".to_vec(), b"data".to_vec(), None, None)
            .unwrap();
        let bytes = builder.to_bytes().unwrap();
        let fault = Arc::new(Mutex::new(Fault::default()));
        let options = ArchiveReadOptions::default();
        let archive = parse(&bytes, &fault, options).unwrap();
        fault.lock().unwrap().arm(Some(1));
        let error = archive
            .extract_to_parallel_buffered_with_options(options, |_| Ok(Box::new(io::sink())))
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Io);
        assert_eq!(
            error.entry_context().map(|(name, _)| name),
            Some(b"payload".as_slice())
        );
    }
}

#[test]
fn removed_file_sources_report_io_with_member_context() {
    let directory =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/reader-failure-tests");
    std::fs::create_dir_all(&directory).unwrap();
    for (version, encrypted, bytes) in images()
        .into_iter()
        .filter(|(version, _, _)| matches!(version, ArchiveVersion::Rar30 | ArchiveVersion::Rar50))
    {
        for streaming in [false, true] {
            let path = directory.join(format!(
                "removed-{}-{version:?}-{encrypted}-{streaming}.rar",
                std::process::id()
            ));
            std::fs::write(&path, &bytes).unwrap();
            let mut options = ArchiveReadOptions::with_optional_password(
                encrypted.then_some(b"secret".as_slice()),
            );
            if streaming {
                options = options.with_rar50_buffered_decode_limit(0);
            }
            let archive = ArchiveReader::read_path_with_options(&path, options).unwrap();
            std::fs::remove_file(&path).unwrap();
            let error = archive
                .extract_to_with_options(options, |_| Ok(Box::new(io::sink())))
                .unwrap_err();
            assert_eq!(error.kind(), ErrorKind::Io, "{version:?}: {error}");
            assert_eq!(
                error.entry_context().map(|(name, _)| name),
                Some(b"payload".as_slice())
            );
            let rars::Error::Io(source) = error.root_cause() else {
                panic!("{error}")
            };
            assert_eq!(
                source.source().downcast_ref::<io::Error>().unwrap().kind(),
                io::ErrorKind::NotFound
            );
        }
    }
}

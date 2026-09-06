use rars::{
    ArchiveReadOptions, ArchiveReader, ArchiveVersion, Builder, Error, ErrorKind, ReadCancellation,
};
use std::{
    cell::RefCell,
    io::{self, Write},
    rc::Rc,
};

#[path = "support/scratch.rs"]
mod scratch;

const FORMATS: [ArchiveVersion; 8] = [
    ArchiveVersion::Rar14,
    ArchiveVersion::Rar15,
    ArchiveVersion::Rar20,
    ArchiveVersion::Rar29,
    ArchiveVersion::Rar30,
    ArchiveVersion::Rar40,
    ArchiveVersion::Rar50,
    ArchiveVersion::Rar70,
];

#[test]
fn cancellation_from_the_last_directory_callback_is_not_success() {
    for format in [ArchiveVersion::Rar50, ArchiveVersion::Rar70] {
        let mut builder = Builder::new(format);
        builder.add_directory(b"dir".to_vec(), None, None).unwrap();
        let archive = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
        for parallel in [false, true] {
            let token = ReadCancellation::new();
            let open = |_: &rars::ExtractedEntryMeta| {
                token.cancel();
                Ok(Box::new(io::sink()) as Box<dyn Write>)
            };
            let options = ArchiveReadOptions::new().with_cancellation(&token);
            let result = if parallel {
                archive.extract_to_parallel_buffered_with_options(options, open)
            } else {
                archive.extract_to_with_options(options, open)
            };
            assert_eq!(result.unwrap_err().kind(), ErrorKind::Cancelled);
        }
    }
}

#[test]
fn compressed_encrypted_splits_keep_cancellation_ahead_of_checksum_diagnostics() {
    let mut state = 0x1234_5678u32;
    let noise: Vec<u8> = (0..4096)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect();
    let data = noise.repeat(3);
    for format in [ArchiveVersion::Rar29, ArchiveVersion::Rar50] {
        let mut builder = Builder::new(format)
            .password(Some(b"secret".to_vec()))
            .volume_size(Some(512));
        builder
            .add_bytes(b"split".to_vec(), data.clone(), None, None)
            .unwrap();
        let mut volumes: Vec<_> = builder
            .build_volumes(None)
            .unwrap()
            .into_iter()
            .map(|bytes| ArchiveReader::read_owned(bytes).unwrap())
            .collect();
        assert!(volumes.len() > 1);
        for cancel in [false, true] {
            for buffered in [u64::MAX, 0] {
                // Buffered extraction verifies before publication. Corrupt only
                // the streaming case, where the sink cancellation precedes CRC.
                if cancel && buffered == 0 {
                    match volumes.last_mut().unwrap() {
                        rars::Archive::Rar15To40(a) => {
                            for block in &mut a.blocks {
                                if let rars::rar15_40::Block::File(f) = block {
                                    assert!(!f.is_stored());
                                    f.file_crc ^= 1;
                                }
                            }
                        }
                        rars::Archive::Rar50Plus(a) => {
                            for block in &mut a.blocks {
                                if let rars::rar50::Block::File(f) = block {
                                    assert!(!f.is_stored());
                                    f.data_crc32 = Some(0);
                                    f.hash = None;
                                }
                            }
                        }
                        _ => unreachable!(),
                    }
                }
                let token = ReadCancellation::new();
                let bytes = Rc::new(RefCell::new(Vec::new()));
                let result = rars::extract_volumes_to_with_options(
                    &volumes,
                    ArchiveReadOptions::with_password(b"secret")
                        .with_cancellation(&token)
                        .with_rar50_buffered_decode_limit(buffered),
                    |_| {
                        Ok(Box::new(Sink {
                            bytes: bytes.clone(),
                            cancel: cancel.then(|| token.clone()),
                            fail: false,
                        }))
                    },
                );
                if cancel {
                    assert_eq!(result.unwrap_err().kind(), ErrorKind::Cancelled);
                    assert!((1..=17).contains(&bytes.borrow().len()));
                } else {
                    result.unwrap();
                    assert_eq!(*bytes.borrow(), data);
                }
            }
        }
    }
}

struct Sink {
    bytes: Rc<RefCell<Vec<u8>>>,
    cancel: Option<ReadCancellation>,
    fail: bool,
}
impl Write for Sink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if let Some(token) = &self.cancel {
            token.cancel();
        }
        if self.fail {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        // A short write must return to a cancellation checkpoint, even in
        // buffered parallel publication and after legacy codec I/O adapters.
        let n = bytes.len().min(17);
        self.bytes.borrow_mut().extend_from_slice(&bytes[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn precancelled_parsing_precedes_signature_checks_and_path_opens() {
    let token = ReadCancellation::new();
    token.clone().cancel();
    let options = ArchiveReadOptions::new().with_cancellation(&token);
    let path = scratch::case("cancelled-reader").join("missing.rar");
    let results = [
        ArchiveReader::read_with_options(b"", options).map(|_| ()),
        ArchiveReader::read_owned_with_options(vec![], options).map(|_| ()),
        ArchiveReader::read_path_with_options(&path, options).map(|_| ()),
        rars::rar13::Archive::parse_with_options(b"", options).map(|_| ()),
        rars::rar13::Archive::parse_owned_with_options(vec![], options).map(|_| ()),
        rars::rar13::Archive::parse_path_with_options(&path, options).map(|_| ()),
        rars::rar15_40::Archive::parse_with_options(b"", options).map(|_| ()),
        rars::rar15_40::Archive::parse_owned_with_options(vec![], options).map(|_| ()),
        rars::rar15_40::Archive::parse_path_with_options(&path, options).map(|_| ()),
        rars::rar50::Archive::parse_with_options(b"", options).map(|_| ()),
        rars::rar50::Archive::parse_owned_with_options(vec![], options).map(|_| ()),
        rars::rar50::Archive::parse_path_with_options(&path, options).map(|_| ()),
    ];
    for result in results {
        assert_eq!(result.unwrap_err().kind(), ErrorKind::Cancelled);
    }
}

#[test]
fn extraction_observes_callbacks_without_retaining_parse_policy() {
    for format in FORMATS {
        for stored in [true, false] {
            let mut builder = Builder::new(format).store(stored);
            for name in [b"first".as_slice(), b"second"] {
                builder
                    .add_bytes(name.to_vec(), vec![42; 8192], None, None)
                    .unwrap();
            }
            let parse_token = ReadCancellation::new();
            let archive = ArchiveReader::read_owned_with_options(
                builder.to_bytes().unwrap(),
                ArchiveReadOptions::new().with_cancellation(&parse_token),
            )
            .unwrap();
            parse_token.cancel();
            for parallel in [false, true] {
                for buffered in [0, u64::MAX] {
                    // None, active token, pre-cancelled, open callback, short
                    // output callback, real open failure, real sink failure.
                    for mode in 0..7 {
                        let token = ReadCancellation::new();
                        if mode == 2 {
                            token.cancel();
                        }
                        let mut options =
                            ArchiveReadOptions::new().with_rar50_buffered_decode_limit(buffered);
                        if mode != 0 {
                            options = options.with_cancellation(&token);
                        }
                        let bytes = Rc::new(RefCell::new(Vec::new()));
                        let mut opened = 0;
                        let open = |_: &rars::ExtractedEntryMeta| {
                            opened += 1;
                            if mode == 3 || mode == 5 {
                                token.cancel();
                            }
                            if mode == 5 {
                                return Err(Error::from(io::Error::from(
                                    io::ErrorKind::PermissionDenied,
                                )));
                            }
                            Ok(Box::new(Sink {
                                bytes: bytes.clone(),
                                cancel: (mode == 4 || mode == 6).then(|| token.clone()),
                                fail: mode == 6,
                            }) as Box<dyn Write>)
                        };
                        let result = if parallel {
                            archive.extract_to_parallel_buffered_with_options(options, open)
                        } else {
                            archive.extract_to_with_options(options, open)
                        };
                        match mode {
                            0 | 1 => {
                                result.unwrap();
                                assert_eq!(*bytes.borrow(), vec![42; 16384]);
                                assert_eq!(opened, 2);
                            }
                            2..=4 => {
                                assert_eq!(
                                    result.unwrap_err().kind(),
                                    ErrorKind::Cancelled,
                                    "{format:?}, mode {mode}"
                                );
                                assert_eq!(opened, usize::from(mode != 2));
                                if mode == 4 {
                                    assert!((1..=17).contains(&bytes.borrow().len()));
                                } else {
                                    assert!(bytes.borrow().is_empty());
                                }
                            }
                            _ => {
                                let err = result.unwrap_err();
                                if mode == 5 {
                                    assert!(
                                        matches!(err.root_cause(), Error::Io(e) if e.kind == io::ErrorKind::PermissionDenied)
                                    );
                                } else {
                                    // Older codecs already map sink errors to codec errors.
                                    // Cancellation must not change that existing failure.
                                    let open = |_: &rars::ExtractedEntryMeta| {
                                        Ok(Box::new(Sink {
                                            bytes: Rc::default(),
                                            cancel: None,
                                            fail: true,
                                        })
                                            as Box<dyn Write>)
                                    };
                                    let options = ArchiveReadOptions::new()
                                        .with_rar50_buffered_decode_limit(buffered);
                                    let baseline = if parallel {
                                        archive.extract_to_parallel_buffered_with_options(
                                            options, open,
                                        )
                                    } else {
                                        archive.extract_to_with_options(options, open)
                                    }
                                    .unwrap_err();
                                    assert_eq!(
                                        format!("{:?}", err.root_cause()),
                                        format!("{:?}", baseline.root_cause())
                                    );
                                    assert_ne!(err.kind(), ErrorKind::Cancelled);
                                }
                                assert_eq!(opened, 1);
                                assert!(bytes.borrow().is_empty());
                            }
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn cancellation_stops_solid_history_and_encrypted_split_extraction() {
    for format in [
        ArchiveVersion::Rar15,
        ArchiveVersion::Rar29,
        ArchiveVersion::Rar50,
    ] {
        let mut b = Builder::new(format).solid(true);
        for name in [b"discarded".as_slice(), b"wanted"] {
            b.add_bytes(name.to_vec(), vec![42; 8192], None, None)
                .unwrap();
        }
        let a = ArchiveReader::read_owned(b.to_bytes().unwrap()).unwrap();
        let token = ReadCancellation::new();
        let mut opened = 0;
        let err = a
            .extract_to_with_options(ArchiveReadOptions::new().with_cancellation(&token), |_| {
                opened += 1;
                Ok(Box::new(Sink {
                    bytes: Rc::default(),
                    cancel: Some(token.clone()),
                    fail: false,
                }))
            })
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Cancelled);
        assert_eq!(opened, 1);
    }
    for format in [
        ArchiveVersion::Rar14,
        ArchiveVersion::Rar20,
        ArchiveVersion::Rar29,
        ArchiveVersion::Rar50,
    ] {
        let mut b = Builder::new(format)
            .store(true)
            .volume_size(Some(512))
            .password((format != ArchiveVersion::Rar14).then(|| b"secret".to_vec()));
        b.add_bytes(b"split".to_vec(), vec![42; 2048], None, None)
            .unwrap();
        let volumes: Vec<_> = b
            .build_volumes(None)
            .unwrap()
            .into_iter()
            .map(|bytes| ArchiveReader::read_owned(bytes).unwrap())
            .collect();
        assert!(volumes.len() > 1);
        for cancel in [false, true] {
            let token = ReadCancellation::new();
            let bytes = Rc::new(RefCell::new(Vec::new()));
            let result = rars::extract_volumes_to_with_options(
                &volumes,
                ArchiveReadOptions::with_password(b"secret").with_cancellation(&token),
                |_| {
                    Ok(Box::new(Sink {
                        bytes: bytes.clone(),
                        cancel: cancel.then(|| token.clone()),
                        fail: false,
                    }))
                },
            );
            if cancel {
                assert_eq!(result.unwrap_err().kind(), ErrorKind::Cancelled);
                assert!((1..=17).contains(&bytes.borrow().len()));
            } else {
                result.unwrap();
                assert_eq!(*bytes.borrow(), vec![42; 2048]);
            }
        }
    }
}

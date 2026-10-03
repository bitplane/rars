#![cfg(feature = "write")]

use rars::{
    ArchiveReader, ArchiveVersion, Builder, EntrySource, ErrorKind, WriteOperation, WriteProgress,
    WriteProgressEvent, WriterResources,
};
use std::io::Cursor;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
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
fn source_and_inline_members_have_identical_legacy_output() {
    for format in FORMATS {
        for (store, solid) in [(true, false), (false, false), (false, true)] {
            let payload = b"legacy source payload with repeated data\n".repeat(16);
            let mut inline = Builder::new(format).store(store).solid(solid);
            let mut sources = Builder::new(format).store(store).solid(solid);
            for (name, bytes) in [
                (b"first".as_slice(), payload.as_slice()),
                (b"second", b"second input"),
                (b"empty", b""),
            ] {
                inline
                    .add_bytes(name.to_vec(), bytes.to_vec(), None, None)
                    .unwrap();
                sources
                    .add_source(name.to_vec(), EntrySource::from_bytes(bytes), None, None)
                    .unwrap();
            }
            let expected = inline.to_bytes().unwrap();
            let actual = sources.to_bytes().unwrap();
            let mut streamed = Vec::new();
            sources
                .write_to(&mut streamed, &WriterResources::default(), None)
                .unwrap();
            assert_eq!(streamed, expected);
            assert_eq!(actual, expected, "{format:?} store={store} solid={solid}");
            let archive = ArchiveReader::read_owned(actual).unwrap();
            assert_eq!(
                archive.read_member(b"first", None).unwrap().unwrap(),
                payload
            );
            assert_eq!(
                archive.read_member(b"second", None).unwrap().unwrap(),
                b"second input"
            );
            assert_eq!(archive.read_member(b"empty", None).unwrap().unwrap(), b"");
        }
    }
}

#[test]
fn compression_start_can_cancel_before_any_legacy_source_is_opened() {
    struct Stop(AtomicBool);
    impl WriteProgress for Stop {
        fn report(&self, event: WriteProgressEvent<'_>) {
            if matches!(
                event,
                WriteProgressEvent::OperationStarted {
                    operation: WriteOperation::Compression,
                    ..
                }
            ) {
                self.0.store(true, Ordering::Relaxed);
            }
        }
        fn is_cancelled(&self) -> bool {
            self.0.load(Ordering::Relaxed)
        }
    }
    for format in FORMATS {
        let opens = Arc::new(AtomicUsize::new(0));
        let mut builder = Builder::new(format).store(true);
        for name in [b"first", b"other"] {
            let opens = opens.clone();
            builder
                .add_source(
                    name.to_vec(),
                    EntrySource::from_opener(1, move || {
                        opens.fetch_add(1, Ordering::Relaxed);
                        Ok(Box::new(Cursor::new(vec![42])))
                    }),
                    None,
                    None,
                )
                .unwrap();
        }
        let mut output = Vec::new();
        let error = builder
            .write_to(
                &mut output,
                &WriterResources::default(),
                Some(&Stop(AtomicBool::new(false))),
            )
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Cancelled);
        assert_eq!(opens.load(Ordering::Relaxed), 0, "{format:?}");
        // A streaming sink may retain the archive prefix on failure.
    }
}

#[test]
fn stored_source_changes_are_detected_during_verified_emission() {
    for format in FORMATS {
        let opens = Arc::new(AtomicUsize::new(0));
        let mut builder = Builder::new(format).store(true);
        let source_opens = opens.clone();
        builder
            .add_source(
                b"source".to_vec(),
                EntrySource::from_opener(1, move || {
                    let value = if source_opens.fetch_add(1, Ordering::Relaxed) == 0 {
                        b'A'
                    } else {
                        b'B'
                    };
                    Ok(Box::new(Cursor::new(vec![value])))
                }),
                None,
                None,
            )
            .unwrap();
        let mut output = Vec::new();
        let error = builder
            .write_to(&mut output, &WriterResources::default(), None)
            .unwrap_err();
        assert_eq!(
            error.kind(),
            ErrorKind::SourceChanged,
            "{format:?}: {error}"
        );
        assert_eq!(error.entry_context().unwrap().0, b"source");
        // A streaming sink may retain the archive prefix on failure.
    }
}

#[test]
fn multiple_legacy_volume_inputs_are_refused_without_opening_them() {
    for format in FORMATS {
        let mut builder = Builder::new(format).store(true).volume_size(Some(64));
        for name in [b"first", b"other"] {
            builder
                .add_source(
                    name.to_vec(),
                    EntrySource::from_opener(1, || panic!("invalid volume plan opened a source")),
                    None,
                    None,
                )
                .unwrap();
        }
        assert_eq!(
            builder.build_volumes(None).unwrap_err().kind(),
            ErrorKind::InvalidArgument
        );
    }
}

#[test]
fn legacy_builder_emits_before_opening_later_sources() {
    use std::io::Write;
    use std::sync::Mutex;
    struct Sink(Arc<Mutex<Vec<u8>>>);
    impl Write for Sink {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            // Exercise short writes as well as direct emission.
            let n = bytes.len().min(17);
            self.0.lock().unwrap().extend_from_slice(&bytes[..n]);
            Ok(n)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            panic!("builder must not flush caller-owned output")
        }
    }
    for format in FORMATS {
        for (store, solid) in [(true, false), (false, false), (false, true)] {
            let output = Arc::new(Mutex::new(Vec::new()));
            let mut builder = Builder::new(format).store(store).solid(solid);
            builder
                .add_bytes(b"first".to_vec(), b"first member".repeat(100), None, None)
                .unwrap();
            let seen = output.clone();
            builder
                .add_source(
                    b"second".to_vec(),
                    EntrySource::from_opener(6, move || {
                        assert!(
                            !seen.lock().unwrap().is_empty(),
                            "later source opened before emission"
                        );
                        Ok(Box::new(Cursor::new(b"second")))
                    }),
                    None,
                    None,
                )
                .unwrap();
            let events = Mutex::new(Vec::new());
            let progress = |event: WriteProgressEvent<'_>| match event {
                WriteProgressEvent::OperationStarted {
                    operation: WriteOperation::Emission,
                    total_bytes,
                    ..
                } => events.lock().unwrap().push((0, total_bytes, false)),
                WriteProgressEvent::BytesWritten { completed_bytes } => {
                    events.lock().unwrap().push((completed_bytes, None, false))
                }
                WriteProgressEvent::OperationFinished {
                    operation: WriteOperation::Emission,
                    total_bytes,
                    ..
                } => events
                    .lock()
                    .unwrap()
                    .push((total_bytes.unwrap(), total_bytes, true)),
                _ => {}
            };
            builder
                .write_to(
                    &mut Sink(output.clone()),
                    &WriterResources::default(),
                    Some(&progress),
                )
                .unwrap();
            let bytes = output.lock().unwrap().clone();
            let events = events.into_inner().unwrap();
            assert_eq!(events.first(), Some(&(0, None, false)));
            assert_eq!(
                events.last(),
                Some(&(bytes.len() as u64, Some(bytes.len() as u64), true))
            );
            assert!(events.windows(2).all(|pair| pair[0].0 <= pair[1].0));
            let archive = ArchiveReader::read_owned(bytes).unwrap();
            assert_eq!(
                archive.read_member(b"second", None).unwrap().unwrap(),
                b"second"
            );
        }
    }
}

#[test]
fn legacy_output_failure_stops_before_later_source_reads() {
    use std::io::Write;
    struct FailingSink;
    impl Write for FailingSink {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("injected sink failure"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    for format in FORMATS {
        let mut builder = Builder::new(format).store(true);
        builder
            .add_source(
                b"never-opened".to_vec(),
                EntrySource::from_opener(1, || panic!("failed output opened a source")),
                None,
                None,
            )
            .unwrap();
        let finished = AtomicBool::new(false);
        let progress = |event: WriteProgressEvent<'_>| {
            if matches!(
                event,
                WriteProgressEvent::OperationFinished {
                    operation: WriteOperation::Emission,
                    ..
                }
            ) {
                finished.store(true, Ordering::Relaxed);
            }
        };
        let error = builder
            .write_to(
                &mut FailingSink,
                &WriterResources::default(),
                Some(&progress),
            )
            .unwrap_err();
        assert!(
            error.to_string().contains("injected sink failure"),
            "{format:?}: {error}"
        );
        assert!(!finished.load(Ordering::Relaxed));
    }
}

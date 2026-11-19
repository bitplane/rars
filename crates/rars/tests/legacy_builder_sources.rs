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

/// Counts every byte handed to a volume, header patches included.
struct CountingVolume {
    inner: Cursor<Vec<u8>>,
    written: Arc<AtomicUsize>,
}

impl std::io::Write for CountingVolume {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.written.fetch_add(bytes.len(), Ordering::Relaxed);
        self.inner.write(bytes)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl std::io::Seek for CountingVolume {
    fn seek(&mut self, to: std::io::SeekFrom) -> std::io::Result<u64> {
        self.inner.seek(to)
    }
}

struct CountingVolumes(Arc<AtomicUsize>);

impl rars::rar50::VolumeSink for CountingVolumes {
    fn start_volume(&mut self, _index: u64) -> rars::Result<Box<dyn rars::rar50::VolumeOutput>> {
        Ok(Box::new(CountingVolume {
            inner: Cursor::new(Vec::new()),
            written: self.0.clone(),
        }))
    }
}

/// RAR 1.3 splits one payload, so it refuses a second input before opening
/// either; RAR 1.5 to 4.x take both and open each only when its turn comes.
#[test]
fn legacy_volume_inputs_are_opened_only_when_their_member_is_written() {
    const LEN: usize = 3000;
    for format in FORMATS {
        let mut builder = Builder::new(format).store(true).volume_size(Some(1024));
        if matches!(format, ArchiveVersion::Rar13 | ArchiveVersion::Rar14) {
            for name in [b"first", b"other"] {
                builder
                    .add_source(
                        name.to_vec(),
                        EntrySource::from_opener(1, || {
                            panic!("invalid volume plan opened a source")
                        }),
                        None,
                        None,
                    )
                    .unwrap();
            }
            assert_eq!(
                builder.build_volumes(None).unwrap_err().kind(),
                ErrorKind::InvalidArgument
            );
            continue;
        }
        let written = Arc::new(AtomicUsize::new(0));
        let first_opened = Arc::new(AtomicBool::new(false));
        let opened = first_opened.clone();
        builder
            .add_source(
                b"first".to_vec(),
                EntrySource::from_opener(LEN as u64, move || {
                    opened.store(true, Ordering::Relaxed);
                    Ok(Box::new(Cursor::new(vec![b'a'; LEN])))
                }),
                None,
                None,
            )
            .unwrap();
        let seen = written.clone();
        let first_seen = first_opened.clone();
        builder
            .add_source(
                b"other".to_vec(),
                EntrySource::from_opener(LEN as u64, move || {
                    assert!(first_seen.load(Ordering::Relaxed));
                    let so_far = seen.load(Ordering::Relaxed);
                    assert!(
                        so_far >= LEN,
                        "{format:?}: second source opened after {so_far} bytes"
                    );
                    Ok(Box::new(Cursor::new(vec![b'b'; LEN])))
                }),
                None,
                None,
            )
            .unwrap();
        builder
            .write_volumes_to(
                &mut CountingVolumes(written.clone()),
                &WriterResources::default(),
                None,
            )
            .unwrap();
        assert!(written.load(Ordering::Relaxed) > 2 * LEN, "{format:?}");
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

#[cfg(feature = "parallel")]
#[test]
fn ordinary_legacy_sources_keep_parallel_preparation() {
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(2)
        .build()
        .unwrap();
    pool.install(|| {
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let mut builder = Builder::new(ArchiveVersion::Rar29).store(true);
        for value in 0..2u8 {
            let barrier = barrier.clone();
            let opens = AtomicUsize::new(0);
            builder
                .add_source(
                    vec![b'a' + value],
                    EntrySource::from_opener(1, move || {
                        if opens.fetch_add(1, Ordering::Relaxed) == 0 {
                            // Both independent sources must enter preparation together.
                            barrier.wait();
                        }
                        Ok(Box::new(Cursor::new(vec![value])))
                    }),
                    None,
                    None,
                )
                .unwrap();
        }
        let archive = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
        for value in 0..2u8 {
            assert_eq!(
                archive
                    .read_member_at(value as usize, None)
                    .unwrap()
                    .unwrap(),
                [value]
            );
        }
    });
}

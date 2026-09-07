use rars::{
    ArchiveVersion, Builder, ErrorKind, WriteCancellation, WriteOperation, WriteProgress,
    WriteProgressEvent, WriterResources,
};
use std::{
    io::{self, Write},
    sync::atomic::{AtomicBool, Ordering},
};

#[path = "support/scratch.rs"]
mod scratch;

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
fn resource_cancellation_stops_source_loading() {
    use rars::EntrySource;
    use std::io::{Cursor, Read, Seek, SeekFrom};
    struct Source {
        token: WriteCancellation,
        bytes: Cursor<Vec<u8>>,
    }
    impl Read for Source {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            self.token.cancel();
            self.bytes.read(bytes)
        }
    }
    impl Seek for Source {
        fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
            self.bytes.seek(pos)
        }
    }
    for format in FORMATS {
        for precancel in [false, true] {
            let token = WriteCancellation::new();
            let source_token = token.clone();
            let source = EntrySource::from_opener(100_000, move || {
                assert!(!precancel, "cancelled writer opened its source");
                Ok(Box::new(Source {
                    token: source_token.clone(),
                    bytes: Cursor::new(vec![42; 100_000]),
                }))
            });
            let mut builder = Builder::new(format).store(true);
            builder
                .add_source(b"source".to_vec(), source, None, None)
                .unwrap();
            if precancel {
                token.cancel();
            }
            let resources = WriterResources::default().with_cancellation(token);
            let mut output = Vec::new();
            assert_eq!(
                builder
                    .write_to(&mut output, &resources, None)
                    .unwrap_err()
                    .kind(),
                ErrorKind::Cancelled
            );
            assert!(output.is_empty());
        }
    }
}

struct Stop {
    operation: WriteOperation,
    finished: bool,
    cancelled: AtomicBool,
}
impl Stop {
    fn new(operation: WriteOperation, finished: bool) -> Self {
        Self {
            operation,
            finished,
            cancelled: AtomicBool::new(false),
        }
    }
}
impl WriteProgress for Stop {
    fn report(&self, event: WriteProgressEvent<'_>) {
        let stop = match event {
            WriteProgressEvent::Advanced {
                operation,
                completed_bytes,
                ..
            } => !self.finished && operation == self.operation && completed_bytes > 0,
            WriteProgressEvent::OperationFinished { operation, .. } => {
                self.finished && operation == self.operation
            }
            _ => false,
        };
        if stop {
            self.cancelled.store(true, Ordering::Relaxed);
        }
    }
    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }
}

fn builder(format: ArchiveVersion, store: bool) -> Builder {
    let mut builder = Builder::new(format).store(store);
    builder
        .add_bytes(
            b"payload".to_vec(),
            b"legacy cancellation\n".repeat(8000),
            None,
            None,
        )
        .unwrap();
    builder
}

#[test]
fn cancellation_during_preparation_and_completion_preserves_destination() {
    let scratch = scratch::case("legacy-writer-cancel");
    let destination = scratch.join("archive.rar");
    for format in FORMATS {
        for store in [false, true] {
            let builder = builder(format, store);
            for operation in [WriteOperation::Compression, WriteOperation::Emission] {
                for finished in [false, true] {
                    std::fs::write(&destination, b"original").unwrap();
                    let stop = Stop::new(operation, finished);
                    let error = builder
                        .write_to_path(&destination, Some(&stop))
                        .unwrap_err();
                    assert_eq!(
                        error.kind(),
                        ErrorKind::Cancelled,
                        "{format:?}, {store}, {operation:?}"
                    );
                    assert_eq!(std::fs::read(&destination).unwrap(), b"original");
                    assert_eq!(std::fs::read_dir(&scratch).unwrap().count(), 1);
                }
            }
            let passive = |_: WriteProgressEvent<'_>| {};
            assert_eq!(
                builder.to_bytes().unwrap(),
                builder.to_bytes_with_progress(Some(&passive)).unwrap()
            );
        }
    }
}

#[test]
fn resource_token_interrupts_short_output_writes() {
    struct Sink {
        token: WriteCancellation,
        calls: usize,
    }
    impl Write for Sink {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.calls += 1;
            self.token.cancel();
            Ok(bytes.len().min(17))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    for format in FORMATS {
        let token = WriteCancellation::new();
        let resources = WriterResources::default().with_cancellation(token.clone());
        let mut sink = Sink { token, calls: 0 };
        assert_eq!(
            builder(format, true)
                .write_to(&mut sink, &resources, None)
                .unwrap_err()
                .kind(),
            ErrorKind::Cancelled
        );
        assert_eq!(sink.calls, 1);
    }
}

#[test]
fn cancellation_after_a_volume_does_not_return_a_partial_set() {
    struct StopVolume(AtomicBool);
    impl WriteProgress for StopVolume {
        fn report(&self, event: WriteProgressEvent<'_>) {
            if matches!(event, WriteProgressEvent::VolumeFinished { .. }) {
                self.0.store(true, Ordering::Relaxed);
            }
        }
        fn is_cancelled(&self) -> bool {
            self.0.load(Ordering::Relaxed)
        }
    }
    for format in FORMATS {
        for store in [false, true] {
            let stop = StopVolume(AtomicBool::new(false));
            let result = builder(format, store)
                .volume_size(Some(64))
                .build_volumes(Some(&stop));
            assert_eq!(
                result.unwrap_err().kind(),
                ErrorKind::Cancelled,
                "{format:?}, {store}"
            );
        }
    }
}

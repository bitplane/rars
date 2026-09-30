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

#[test]
fn cancellation_from_final_zero_byte_progress_is_not_reported_as_success() {
    struct StopAtFinalAdvance(AtomicBool);
    impl WriteProgress for StopAtFinalAdvance {
        fn report(&self, event: WriteProgressEvent<'_>) {
            if matches!(
                event,
                WriteProgressEvent::Advanced {
                    operation: WriteOperation::Compression,
                    completed_bytes: 0,
                    total_bytes: 0,
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

    let mut builder = Builder::new(ArchiveVersion::Rar30).store(true);
    builder
        .add_bytes(b"empty".to_vec(), Vec::new(), None, None)
        .unwrap();
    let stop = StopAtFinalAdvance(AtomicBool::new(false));
    assert_eq!(
        builder
            .to_bytes_with_progress(Some(&stop))
            .unwrap_err()
            .kind(),
        ErrorKind::Cancelled
    );
}

#[test]
fn compressed_legacy_volume_can_cancel_at_final_progress() {
    use rars::{rar15_40, FeatureSet};
    use std::sync::atomic::AtomicUsize;

    struct StopAfterLastVolume {
        final_volume: AtomicBool,
        checks_after_final: AtomicUsize,
    }
    impl WriteProgress for StopAfterLastVolume {
        fn report(&self, event: WriteProgressEvent<'_>) {
            if let WriteProgressEvent::VolumeFinished {
                volume_number,
                total_volumes: Some(total_volumes),
                ..
            } = event
            {
                if volume_number == total_volumes {
                    self.final_volume.store(true, Ordering::Relaxed);
                }
            }
        }
        fn is_cancelled(&self) -> bool {
            // The volume reporter checks once before returning. Cancel at
            // the wrapper's final compression-progress update after that.
            self.final_volume.load(Ordering::Relaxed)
                && self.checks_after_final.fetch_add(1, Ordering::Relaxed) != 0
        }
    }

    let data = b"legacy volume compression".repeat(100);
    let entry = rar15_40::FileEntry {
        name: b"file",
        data: &data,
        file_time: 0,
        file_attr: 0x20,
        host_os: 3,
        password: None,
        file_comment: None,
    };
    let progress = StopAfterLastVolume {
        final_volume: AtomicBool::new(false),
        checks_after_final: AtomicUsize::new(0),
    };
    let result = rar15_40::write_compressed_volumes_with_progress(
        entry,
        rar15_40::WriterOptions::new(ArchiveVersion::Rar29, FeatureSet::default()),
        1024,
        Some(&progress),
    );
    assert_eq!(result.unwrap_err().kind(), ErrorKind::Cancelled);
    assert!(progress.final_volume.load(Ordering::Relaxed));
    assert!(progress.checks_after_final.load(Ordering::Relaxed) >= 2);
}

#[test]
fn compressed_legacy_volume_preserves_cancellation_from_codec() {
    use rars::{rar15_40, FeatureSet};

    let data = b"a repeating legacy volume member ".repeat(4096);
    let entry = rar15_40::FileEntry {
        name: b"file",
        data: &data,
        file_time: 0,
        file_attr: 0x20,
        host_os: 3,
        password: None,
        file_comment: None,
    };
    let progress = Stop::new(WriteOperation::Compression, false);
    let error = rar15_40::write_compressed_volumes_with_progress(
        entry,
        rar15_40::WriterOptions::new(ArchiveVersion::Rar29, FeatureSet::default()),
        1024,
        Some(&progress),
    )
    .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Cancelled);
    assert!(progress.cancelled.load(Ordering::Relaxed));
}

#[test]
fn rar13_compressed_volume_preserves_cancellation_from_codec() {
    use rars::rar13;

    let data = b"a repeating RAR 1.3 volume member ".repeat(4096);
    let entry = rar13::FileEntry {
        name: b"file",
        data: &data,
        file_time: 0,
        file_attr: 0x20,
        password: None,
        file_comment: None,
    };
    let progress = Stop::new(WriteOperation::Compression, false);
    let error = rar13::write_compressed_volumes_with_progress(
        entry,
        rar13::WriterOptions::default(),
        1024,
        Some(&progress),
    )
    .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Cancelled);
    assert!(progress.cancelled.load(Ordering::Relaxed));
}

#[test]
fn rar29_filter_search_preserves_cancellation() {
    use rars::{rar15_40, FeatureSet, FilterPolicy};

    let mut state = 0x1357_9bdfu32;
    let data: Vec<u8> = (0..16_384)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect();
    let entry = rar15_40::FileEntry {
        name: b"binary",
        data: &data,
        file_time: 0,
        file_attr: 0x20,
        host_os: 3,
        password: None,
        file_comment: None,
    };
    let progress = Stop::new(WriteOperation::Compression, false);
    let error = rar15_40::write_rar29_compressed_archive_with_filter_policy_and_progress(
        &[entry],
        rar15_40::WriterOptions::new(ArchiveVersion::Rar29, FeatureSet::default()),
        FilterPolicy::Auto,
        Some(&progress),
    )
    .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Cancelled);
    assert!(progress.cancelled.load(Ordering::Relaxed));
}

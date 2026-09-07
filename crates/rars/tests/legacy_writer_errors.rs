use rars::{
    rar13, rar15_40, ArchiveVersion, Builder, EntrySource, Error, ErrorKind, FeatureSet,
    MemberCoding, WriteCancellation, WriterResources,
};
use std::{
    io::{self, Cursor, Write},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
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

fn write(
    format: ArchiveVersion,
    source: EntrySource,
    compressed: bool,
    solid: bool,
    resources: &WriterResources,
    output: &mut dyn Write,
) -> rars::Result<()> {
    let mut features = FeatureSet::store_only();
    features.solid = solid;
    let coding = if compressed {
        MemberCoding::Compressed
    } else {
        MemberCoding::Stored
    };
    if matches!(format, ArchiveVersion::Rar13 | ArchiveVersion::Rar14) {
        let entries = [
            rar13::StreamingEntry::new(
                b"first".to_vec(),
                EntrySource::from_bytes(b"good".to_vec()),
            ),
            rar13::StreamingEntry::new(b"second".to_vec(), source),
        ];
        rar13::write_streaming_archive_to(
            &entries,
            rar13::WriterOptions::new(format, features),
            coding,
            None,
            resources,
            None,
            output,
        )
    } else {
        let entries = [
            rar15_40::StreamingEntry::new(
                b"first".to_vec(),
                EntrySource::from_bytes(b"good".to_vec()),
            ),
            rar15_40::StreamingEntry::new(b"second".to_vec(), source),
        ];
        rar15_40::write_streaming_archive_to(
            &entries,
            rar15_40::WriterOptions::new(format, features),
            coding,
            None,
            resources,
            None,
            output,
        )
    }
}

#[test]
fn source_failures_identify_the_member_in_serial_and_parallel_preparation() {
    for format in FORMATS {
        for (compressed, solid) in [(false, false), (true, false), (true, true)] {
            let source = EntrySource::from_opener(4, || {
                Err(io::Error::new(io::ErrorKind::PermissionDenied, "source denied").into())
            });
            let error = write(
                format,
                source,
                compressed,
                solid,
                &WriterResources::default(),
                &mut Vec::new(),
            )
            .unwrap_err();
            assert_eq!(error.kind(), ErrorKind::Io);
            assert_eq!(error.entry_context(), Some((&b"second"[..], "preparing")));
            assert!(
                matches!(error.root_cause(), Error::Io(io) if io.kind == std::io::ErrorKind::PermissionDenied)
            );
        }
    }
}

#[test]
fn changed_contents_and_lengths_have_the_same_source_changed_category() {
    for format in FORMATS {
        for same_length in [false, true] {
            let opens = Arc::new(AtomicUsize::new(0));
            let source = EntrySource::from_opener(4, move || {
                let data = if opens.fetch_add(1, Ordering::Relaxed) == 0 {
                    b"good".to_vec()
                } else if same_length {
                    b"evil".to_vec()
                } else {
                    b"short".to_vec()
                };
                Ok(Box::new(Cursor::new(data)))
            });
            let error = write(
                format,
                source,
                false,
                false,
                &WriterResources::default(),
                &mut Vec::new(),
            )
            .unwrap_err();
            assert_eq!(error.kind(), ErrorKind::SourceChanged, "{format:?}");
            assert_eq!(error.entry_context(), Some((&b"second"[..], "writing")));
        }
    }
}

#[test]
fn builder_source_materialization_identifies_the_member() {
    for format in FORMATS {
        let mut builder = Builder::new(format);
        builder
            .add_source(
                b"source".to_vec(),
                EntrySource::from_opener(3, || Ok(Box::new(Cursor::new(vec![1])))),
                None,
                None,
            )
            .unwrap();
        let error = builder.to_bytes().unwrap_err();
        assert_eq!(error.kind(), ErrorKind::SourceChanged);
        assert_eq!(
            error.entry_context(),
            Some((&b"source"[..], "reading source"))
        );
    }
}

#[test]
fn member_payload_output_failure_retains_io_kind_and_member() {
    use std::sync::atomic::AtomicBool;
    struct Output(Arc<AtomicBool>);
    impl Write for Output {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.0.load(Ordering::Relaxed) {
                Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "payload sink closed",
                ))
            } else {
                Ok(bytes.len())
            }
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    for format in FORMATS {
        let broken = Arc::new(AtomicBool::new(false));
        let source = EntrySource::from_opener(4, {
            let broken = broken.clone();
            let opens = AtomicUsize::new(0);
            move || {
                if opens.fetch_add(1, Ordering::Relaxed) == 1 {
                    broken.store(true, Ordering::Relaxed);
                }
                Ok(Box::new(Cursor::new(b"good".to_vec())))
            }
        });
        let error = write(
            format,
            source,
            false,
            false,
            &WriterResources::default(),
            &mut Output(broken),
        )
        .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Io);
        assert_eq!(error.entry_context(), Some((&b"second"[..], "writing")));
    }
}

#[test]
fn cancellation_and_shared_output_failures_do_not_blame_a_member() {
    struct BrokenOutput;
    impl Write for BrokenOutput {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    for format in FORMATS {
        let error = write(
            format,
            EntrySource::from_bytes(b"good".to_vec()),
            false,
            false,
            &WriterResources::default(),
            &mut BrokenOutput,
        )
        .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Io);
        assert_eq!(error.entry_context(), None);

        let token = WriteCancellation::new();
        let source = EntrySource::from_opener(4, {
            let token = token.clone();
            move || {
                token.cancel();
                Ok(Box::new(Cursor::new(b"good".to_vec())))
            }
        });
        let error = write(
            format,
            source,
            false,
            false,
            &WriterResources::default().with_cancellation(token),
            &mut Vec::new(),
        )
        .unwrap_err();
        assert_eq!(error, Error::Cancelled);
    }
}

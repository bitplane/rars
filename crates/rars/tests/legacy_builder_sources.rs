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
        assert!(output.is_empty());
    }
}

#[test]
fn stored_source_changes_are_detected_before_builder_output_is_emitted() {
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
        assert!(output.is_empty());
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

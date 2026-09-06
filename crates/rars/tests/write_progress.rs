#[path = "support/scratch.rs"]
mod scratch;

use rars::rar50::{self, ArchiveEntry, ArchiveExtras, FilterPolicy, WriterOptions};
use rars::{
    ArchiveVersion, EntrySource, FeatureSet, WriteOperation, WriteProgressEvent, WriterResources,
};
use std::io::{Cursor, Write};
use std::sync::{Arc, Mutex};

#[test]
fn member_events_surround_work_and_emission_surrounds_output() {
    for (level, solid, policy) in [
        (0, false, FilterPolicy::None),
        (1, false, FilterPolicy::None),
        (1, true, FilterPolicy::None),
        (1, false, FilterPolicy::Auto),
    ] {
        let events = Arc::new(Mutex::new(Vec::new()));
        let entries: Vec<_> = (0..8)
            .map(|index| {
                let events = events.clone();
                let data = if index == 3 {
                    Vec::new()
                } else {
                    vec![b'a' + index as u8; 1024]
                };
                ArchiveEntry::new(
                    format!("member-{index}").into_bytes(),
                    EntrySource::from_opener(data.len() as u64, move || {
                        events.lock().unwrap().push(('r', index));
                        Ok(Box::new(Cursor::new(data.clone())))
                    }),
                )
            })
            .collect();
        let report = |event: WriteProgressEvent<'_>| {
            let mut events = events.lock().unwrap();
            match event {
                WriteProgressEvent::EntryStarted { index, .. } => events.push(('s', index)),
                WriteProgressEvent::EntryFinished { index, .. } => events.push(('f', index)),
                WriteProgressEvent::Advanced {
                    operation: WriteOperation::Compression,
                    completed_bytes,
                    total_bytes,
                    ..
                } => {
                    assert!(completed_bytes <= total_bytes);
                    if let Some((_, previous)) = events.iter().rev().find(|(kind, _)| *kind == 'a')
                    {
                        assert!(completed_bytes as usize >= *previous);
                    }
                    events.push(('a', completed_bytes as usize));
                }
                WriteProgressEvent::OperationStarted {
                    operation: WriteOperation::Emission,
                    ..
                } => events.push(('e', 0)),
                WriteProgressEvent::OperationFinished {
                    operation: WriteOperation::Emission,
                    ..
                } => events.push(('z', 0)),
                _ => {}
            }
        };
        struct Output<'a>(&'a Mutex<Vec<(char, usize)>>);
        impl Write for Output<'_> {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                let mut events = self.0.lock().unwrap();
                assert!(events.contains(&('e', 0)));
                assert!(!events.contains(&('z', 0)));
                events.push(('w', 0));
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let scratch = scratch::case("writer-progress");
        let resources = WriterResources::default().with_temp_dir(&*scratch);
        let mut features = FeatureSet::store_only();
        features.solid = solid;
        rar50::write_streaming_archive_with_progress(
            &entries,
            WriterOptions::new(ArchiveVersion::Rar50, features).with_compression_level(level),
            ArchiveExtras::default().with_filter_policy(policy),
            &resources,
            Some(&report),
            &mut Output(&events),
        )
        .unwrap();
        let events = events.lock().unwrap();
        let position = |event| events.iter().position(|value| *value == event).unwrap();
        for index in 0..entries.len() {
            assert_eq!(
                events
                    .iter()
                    .filter(|value| **value == ('s', index))
                    .count(),
                1
            );
            assert_eq!(
                events
                    .iter()
                    .filter(|value| **value == ('f', index))
                    .count(),
                1
            );
            assert!(position(('s', index)) < position(('r', index)));
            assert!(position(('r', index)) < position(('f', index)));
            assert!(position(('f', index)) < position(('e', 0)));
        }
        assert!(position(('w', 0)) < position(('z', 0)));
    }
}

#[test]
fn cancellation_token_stops_input_preparation_without_a_reporter() {
    use rars::{Error, WriteCancellation};
    use std::io::{Read, Seek, SeekFrom};
    struct Input {
        data: Cursor<Vec<u8>>,
        cancel: WriteCancellation,
    }
    impl Read for Input {
        fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
            let len = bytes.len().min(64 * 1024);
            let count = self.data.read(&mut bytes[..len])?;
            self.cancel.cancel();
            Ok(count)
        }
    }
    impl Seek for Input {
        fn seek(&mut self, from: SeekFrom) -> std::io::Result<u64> {
            self.data.seek(from)
        }
    }
    for (level, solid, policy) in [
        (0, false, FilterPolicy::None),
        (1, false, FilterPolicy::None),
        (1, true, FilterPolicy::None),
        (1, false, FilterPolicy::Auto),
    ] {
        let scratch = scratch::case("cancel-preparation");
        let cancel = WriteCancellation::new();
        let resources = WriterResources::default()
            .with_temp_dir(&*scratch)
            .with_cancellation(cancel.clone());
        let entry = ArchiveEntry::new(
            b"input".to_vec(),
            EntrySource::from_opener(256 * 1024, move || {
                Ok(Box::new(Input {
                    data: Cursor::new(vec![b'a'; 256 * 1024]),
                    cancel: cancel.clone(),
                }))
            }),
        );
        let mut features = FeatureSet::store_only();
        features.solid = solid;
        let mut output = Vec::new();
        let result = rar50::write_streaming_archive_to(
            &[entry],
            WriterOptions::new(ArchiveVersion::Rar50, features).with_compression_level(level),
            ArchiveExtras::default().with_filter_policy(policy),
            &resources,
            &mut output,
        );
        assert_eq!(result, Err(Error::Cancelled));
        assert!(output.is_empty());
        assert_eq!(std::fs::read_dir(&*scratch).unwrap().count(), 0);
    }
}

#[test]
fn cancellation_during_output_preserves_partial_output_and_omits_completion() {
    use rars::{Error, WriteCancellation, WriteProgress};
    use std::sync::atomic::{AtomicBool, Ordering};
    for via_callback in [false, true] {
        let scratch = scratch::case("cancel-output");
        let cancel = WriteCancellation::new();
        let resources = WriterResources::default()
            .with_temp_dir(&*scratch)
            .with_cancellation(if via_callback {
                WriteCancellation::new()
            } else {
                cancel.clone()
            });
        struct Reporter {
            cancel: WriteCancellation,
            finished: AtomicBool,
        }
        impl WriteProgress for Reporter {
            fn report(&self, event: WriteProgressEvent<'_>) {
                if matches!(
                    event,
                    WriteProgressEvent::OperationFinished {
                        operation: WriteOperation::Emission,
                        ..
                    }
                ) {
                    self.finished.store(true, Ordering::Relaxed);
                }
            }
            fn is_cancelled(&self) -> bool {
                self.cancel.is_cancelled()
            }
        }
        struct Output {
            cancel: WriteCancellation,
            bytes: Vec<u8>,
        }
        impl Write for Output {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.bytes.extend_from_slice(bytes);
                self.cancel.cancel();
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let reporter = Reporter {
            cancel: cancel.clone(),
            finished: AtomicBool::new(false),
        };
        let mut output = Output {
            cancel,
            bytes: Vec::new(),
        };
        let entry = ArchiveEntry::new(
            b"input".to_vec(),
            EntrySource::from_bytes(vec![b'a'; 128 * 1024]),
        );
        let result = rar50::write_streaming_archive_with_progress(
            &[entry],
            WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only())
                .with_compression_level(0),
            ArchiveExtras::default(),
            &resources,
            Some(&reporter),
            &mut output,
        );
        assert_eq!(result, Err(Error::Cancelled));
        assert!(!output.bytes.is_empty());
        assert!(output.bytes.len() < 128 * 1024);
        assert!(!reporter.finished.load(Ordering::Relaxed));
        assert_eq!(std::fs::read_dir(&*scratch).unwrap().count(), 0);
    }
}

#[test]
fn cancellation_interrupts_encrypted_volume_preparation() {
    use rars::{Error, WriteCancellation};
    use std::io::{Read, Seek, SeekFrom};
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Input {
        data: Cursor<Vec<u8>>,
        cancel: Option<WriteCancellation>,
    }
    impl Read for Input {
        fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
            let count = self.data.read(bytes)?;
            if let Some(cancel) = &self.cancel {
                cancel.cancel();
            }
            Ok(count)
        }
    }
    impl Seek for Input {
        fn seek(&mut self, from: SeekFrom) -> std::io::Result<u64> {
            self.data.seek(from)
        }
    }
    struct NoVolumes;
    impl rar50::VolumeSink for NoVolumes {
        fn start_volume(&mut self, _: u64) -> rars::Result<Box<dyn Write + Send>> {
            panic!("cancelled encryption must not publish a volume");
        }
    }
    let scratch = scratch::case("cancel-volume-encryption");
    let cancel = WriteCancellation::new();
    let resources = WriterResources::default()
        .with_temp_dir(&*scratch)
        .with_cancellation(cancel.clone());
    let opens = AtomicUsize::new(0);
    let entry = ArchiveEntry::new(
        b"input".to_vec(),
        EntrySource::from_opener(256 * 1024, move || {
            Ok(Box::new(Input {
                data: Cursor::new(vec![b'a'; 256 * 1024]),
                cancel: (opens.fetch_add(1, Ordering::Relaxed) > 0).then(|| cancel.clone()),
            }))
        }),
    )
    .with_password(b"secret".to_vec());
    let result = rar50::write_streaming_volumes_to(
        &[entry],
        WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only())
            .with_compression_level(0),
        ArchiveExtras::default(),
        128 * 1024,
        &mut NoVolumes,
        &resources,
    );
    assert_eq!(result, Err(Error::Cancelled));
    assert_eq!(std::fs::read_dir(&*scratch).unwrap().count(), 0);
}

#[test]
fn callback_cancellation_during_encoding_and_recovery_is_typed() {
    use rars::{Error, WriteProgress};
    use std::sync::atomic::{AtomicBool, Ordering};
    struct Reporter {
        phase: WriteOperation,
        cancel: AtomicBool,
    }
    impl WriteProgress for Reporter {
        fn report(&self, event: WriteProgressEvent<'_>) {
            if let WriteProgressEvent::Advanced { operation, .. } = event {
                if operation == self.phase {
                    self.cancel.store(true, Ordering::Relaxed);
                }
            }
        }
        fn is_cancelled(&self) -> bool {
            // A callback may deliver a one-shot request; it must not be lost
            // while the recovery layer translates its I/O error.
            self.cancel.swap(false, Ordering::Relaxed)
        }
    }
    for phase in [WriteOperation::Compression, WriteOperation::Recovery] {
        let scratch = scratch::case("cancel-codec-recovery");
        let resources = WriterResources::default().with_temp_dir(&*scratch);
        let reporter = Reporter {
            phase,
            cancel: AtomicBool::new(false),
        };
        let entry = ArchiveEntry::new(
            b"input".to_vec(),
            EntrySource::from_bytes(vec![b'a'; 128 * 1024]),
        );
        let result = rar50::write_streaming_archive_with_progress(
            &[entry],
            WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only())
                .with_compression_level(if phase == WriteOperation::Compression {
                    1
                } else {
                    0
                }),
            ArchiveExtras::default().with_recovery_percent(Some(5)),
            &resources,
            Some(&reporter),
            &mut Vec::new(),
        );
        assert_eq!(result, Err(Error::Cancelled));
        assert_eq!(std::fs::read_dir(&*scratch).unwrap().count(), 0);
    }
}

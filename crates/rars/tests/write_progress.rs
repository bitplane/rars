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

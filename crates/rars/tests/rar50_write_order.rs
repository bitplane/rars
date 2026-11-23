#![cfg(feature = "write")]

use rars::atomic64::AtomicU64;
use rars::rar50::{self, ArchiveEntry, ArchiveExtras, WriterOptions};
use rars::{ArchiveVersion, EntrySource, FeatureSet, WriterResources};
use std::io::{Cursor, Write};
use std::sync::atomic::Ordering;
use std::sync::{Arc, OnceLock};

struct Counted(Vec<u8>, Arc<AtomicU64>);

impl Write for Counted {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.extend_from_slice(bytes);
        self.1.store(self.0.len() as u64, Ordering::SeqCst);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn member(index: usize) -> Vec<u8> {
    let mut state = index as u32 + 1;
    (0..16 * 1024)
        .map(|offset| {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            if offset % 3 == 0 {
                (state >> 24) as u8
            } else {
                b'a' + (offset % 7) as u8
            }
        })
        .collect()
}

#[test]
fn the_first_member_is_written_before_the_last_is_read() {
    // A solid wave is a run per thread, each at least 1 MiB, so two threads
    // and a small dictionary take these members in several waves.
    let count = 200;
    for (level, solid) in [(3, false), (3, true), (0, false)] {
        let written = Arc::new(AtomicU64::new(0));
        let at_last_open = Arc::new(OnceLock::new());
        let entries: Vec<_> = (0..count)
            .map(|index| {
                let data = member(index);
                let source = if index + 1 == count {
                    let (written, seen) = (Arc::clone(&written), Arc::clone(&at_last_open));
                    EntrySource::from_opener(data.len() as u64, move || {
                        seen.get_or_init(|| written.load(Ordering::SeqCst));
                        Ok(Box::new(Cursor::new(data.clone())))
                    })
                } else {
                    EntrySource::from_bytes(data)
                };
                ArchiveEntry::new(format!("member{index:04}.txt").into_bytes(), source)
                    .with_mtime(Some(0x5000_0000))
            })
            .collect();
        let mut features = FeatureSet::store_only();
        features.solid = solid;
        let options = WriterOptions::new(ArchiveVersion::Rar50, features)
            .with_compression_level(level)
            .with_dictionary_size(256 * 1024);
        let mut output = Counted(Vec::new(), Arc::clone(&written));
        let write = || {
            rar50::write_streaming_archive_to(
                &entries,
                options,
                ArchiveExtras::default(),
                &WriterResources::default(),
                &mut output,
            )
        };
        #[cfg(feature = "parallel")]
        let written_archive = rayon::ThreadPoolBuilder::new()
            .num_threads(2)
            .build()
            .unwrap()
            .install(write);
        #[cfg(not(feature = "parallel"))]
        let written_archive = write();
        written_archive.unwrap();

        let archive = output.0;
        let first = archive
            .windows(14)
            .position(|window| window == b"member0000.txt")
            .unwrap() as u64;
        assert!(
            *at_last_open.get().unwrap() > first,
            "level {level}, solid {solid}: nothing of the first member was written before the last was opened"
        );
        rars::ArchiveReader::read(&archive)
            .unwrap()
            .test(None)
            .unwrap();
    }
}

fn seekable_and_streamed(
    entries: &[ArchiveEntry],
    options: WriterOptions,
    extras: ArchiveExtras<'_>,
) -> (Vec<u8>, Vec<u8>) {
    let resources = WriterResources::default();
    let mut seekable = Cursor::new(Vec::new());
    rar50::write_seekable_archive_to(entries, options, extras.clone(), &resources, &mut seekable)
        .unwrap();
    let mut streamed = Vec::new();
    rar50::write_streaming_archive_to(entries, options, extras, &resources, &mut streamed).unwrap();
    (seekable.into_inner(), streamed)
}

#[test]
fn seekable_and_stream_outputs_extract_the_same_with_every_layout_feature() {
    let data: Vec<Vec<u8>> = [0, 1, 300_000, 40_000, 0, 1_200_000]
        .iter()
        .enumerate()
        .map(|(index, &len)| member(index).into_iter().cycle().take(len).collect())
        .collect();
    let encryption = if cfg!(feature = "encryption") {
        vec![false, true]
    } else {
        vec![false]
    };
    let recovery = if cfg!(feature = "recovery") {
        vec![None, Some(5)]
    } else {
        vec![None]
    };
    for solid in [false, true] {
        for quick_open in [false, true] {
            for &header_encryption in &encryption {
                for &recovery_percent in &recovery {
                    // Quick open is refused with encrypted headers.
                    if quick_open && header_encryption {
                        continue;
                    }
                    let password = header_encryption.then_some(b"secret".as_slice());
                    let entries: Vec<_> = data
                        .iter()
                        .enumerate()
                        .map(|(index, bytes)| {
                            let entry = ArchiveEntry::new(
                                format!("member{index}.bin").into_bytes(),
                                EntrySource::from_bytes(bytes.clone()),
                            )
                            .with_mtime(Some(0x5000_0000));
                            match password {
                                Some(password) => entry.with_password(password.to_vec()),
                                None => entry,
                            }
                        })
                        .collect();
                    let mut features = FeatureSet::store_only();
                    features.solid = solid;
                    features.quick_open = quick_open;
                    features.header_encryption = header_encryption;
                    let options = WriterOptions::new(ArchiveVersion::Rar50, features)
                        .with_compression_level(1);
                    let extras = ArchiveExtras::default().with_recovery_percent(recovery_percent);
                    let (seekable, streamed) = seekable_and_streamed(&entries, options, extras);
                    let case = format!(
                        "solid {solid}, quick open {quick_open}, header encryption \
                         {header_encryption}, recovery {recovery_percent:?}"
                    );
                    if !header_encryption {
                        assert!(seekable == streamed, "{case}: outputs differ");
                    }
                    for archive in [&seekable, &streamed] {
                        let read_options = match password {
                            Some(password) => rars::ArchiveReadOptions::with_password(password),
                            None => rars::ArchiveReadOptions::new(),
                        };
                        let reader =
                            rars::ArchiveReader::read_with_options(archive, read_options).unwrap();
                        reader.test(password).unwrap();
                        for (index, bytes) in data.iter().enumerate() {
                            let name = format!("member{index}.bin");
                            assert_eq!(
                                reader
                                    .read_member(name.as_bytes(), password)
                                    .unwrap()
                                    .as_ref(),
                                Some(bytes),
                                "{case}: {name}"
                            );
                        }
                    }
                }
            }
        }
    }
}

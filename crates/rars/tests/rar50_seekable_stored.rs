#![cfg(feature = "write")]

use rars::atomic64::AtomicU64;
use rars::rar50::{self, ArchiveEntry, ArchiveExtras, WriterOptions};
use rars::{ArchiveVersion, EntrySource, ErrorKind, FeatureSet, WriterResources};
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::sync::atomic::Ordering;
use std::sync::Arc;

fn bytes(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|index| (index as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

struct Counting {
    data: Cursor<Vec<u8>>,
    served: Arc<AtomicU64>,
}

impl Read for Counting {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let read = self.data.read(buffer)?;
        self.served.fetch_add(read as u64, Ordering::Relaxed);
        Ok(read)
    }
}

impl Seek for Counting {
    fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
        self.data.seek(position)
    }
}

fn counted(len: u64, data: Vec<u8>) -> (EntrySource, Arc<AtomicU64>) {
    let served = Arc::new(AtomicU64::new(0));
    let counter = Arc::clone(&served);
    let source = EntrySource::from_opener(len, move || {
        Ok(Box::new(Counting {
            data: Cursor::new(data.clone()),
            served: Arc::clone(&counter),
        }))
    });
    (source, served)
}

fn stored(features: FeatureSet) -> WriterOptions {
    WriterOptions::new(ArchiveVersion::Rar50, features).with_compression_level(0)
}

fn seekable(
    entries: &[ArchiveEntry],
    options: WriterOptions,
    extras: ArchiveExtras<'_>,
) -> rars::Result<Vec<u8>> {
    let mut output = Cursor::new(Vec::new());
    rar50::write_seekable_archive_to(
        entries,
        options,
        extras,
        &WriterResources::default(),
        &mut output,
    )?;
    Ok(output.into_inner())
}

fn streamed(
    entries: &[ArchiveEntry],
    options: WriterOptions,
    extras: ArchiveExtras<'_>,
) -> Vec<u8> {
    let mut output = Vec::new();
    rar50::write_streaming_archive_to(
        entries,
        options,
        extras,
        &WriterResources::default(),
        &mut output,
    )
    .unwrap();
    output
}

#[test]
fn a_stored_member_is_read_once_and_the_archive_matches_the_streamed_one() {
    let sizes = [3 * 1024 * 1024 + 17, 0, 4096, 1];
    let mut entries = Vec::new();
    let mut counters = Vec::new();
    for (index, size) in sizes.into_iter().enumerate() {
        let (source, served) = counted(size as u64, bytes(size, index as u8));
        entries.push(
            ArchiveEntry::new(format!("member{index}.bin").into_bytes(), source)
                .with_mtime(Some(0x5000_0000)),
        );
        counters.push(served);
    }
    let options = stored(FeatureSet::store_only());

    let archive = seekable(&entries, options, ArchiveExtras::default()).unwrap();
    for (served, size) in counters.iter().zip(sizes) {
        assert_eq!(served.swap(0, Ordering::Relaxed), size as u64);
    }
    assert_eq!(
        archive,
        streamed(&entries, options, ArchiveExtras::default())
    );

    let reader = rars::ArchiveReader::read(&archive).unwrap();
    reader.test(None).unwrap();
}

#[test]
fn a_source_of_another_length_than_it_declared_fails_as_changed() {
    for encrypted in [false, true] {
        if encrypted && !cfg!(feature = "encryption") {
            continue;
        }
        // A member over 256 KiB is copied by a pipeline rather than inline.
        for (len, served) in [
            (4096, 4095),
            (4096, 4097),
            (1 << 20, (1 << 20) - 1),
            (1 << 20, (1 << 20) + 1),
        ] {
            let (source, _) = counted(len, bytes(served, 7));
            let entry = ArchiveEntry::new(b"file".to_vec(), source);
            let entry = if encrypted {
                entry.with_password(b"secret".to_vec())
            } else {
                entry
            };
            let error = seekable(
                &[entry],
                stored(FeatureSet::store_only()),
                ArchiveExtras::default(),
            )
            .unwrap_err();
            assert_eq!(
                error.kind(),
                ErrorKind::SourceChanged,
                "encrypted={encrypted}, len={len}, served={served}: {error}"
            );
            assert_eq!(error.entry_context().unwrap().0, b"file");
        }
    }
}

#[test]
#[cfg(feature = "recovery")]
fn the_recovery_record_covers_patched_headers() {
    let data = bytes(300 * 1024, 3);
    let entry = ArchiveEntry::new(b"patched.bin".to_vec(), EntrySource::from_bytes(data));
    let original = seekable(
        &[entry],
        stored(FeatureSet::store_only()),
        ArchiveExtras::default().with_recovery_percent(Some(10)),
    )
    .unwrap();

    // Damage the member's header, which went out as a placeholder, and its data.
    let name = original
        .windows(b"patched.bin".len())
        .position(|window| window == b"patched.bin")
        .unwrap();
    let mut damaged = original.clone();
    damaged[name - 8..name + 4]
        .iter_mut()
        .for_each(|byte| *byte ^= 0xff);
    damaged[name + 4096..name + 4160]
        .iter_mut()
        .for_each(|byte| *byte ^= 0xff);

    let repaired = rars::rar50::repair_inline_recovery_bytes_with_options(
        &damaged,
        rars::ArchiveReadOptions::new(),
    )
    .unwrap();
    assert!(repaired.report.data_repaired);
    assert_eq!(repaired.data, original);
}

#[test]
fn quick_open_repeats_the_patched_headers() {
    let entries: Vec<_> = [2048usize, 0, 7]
        .into_iter()
        .enumerate()
        .map(|(index, len)| {
            ArchiveEntry::new(
                format!("indexed{index}").into_bytes(),
                EntrySource::from_bytes(bytes(len, index as u8)),
            )
            .with_service(rar50::ServiceEntry::new(b"CMT".to_vec(), b"note".to_vec()))
        })
        .collect();
    let mut features = FeatureSet::store_only();
    features.quick_open = true;
    let extras = || ArchiveExtras::default().with_comment(b"archive comment");
    let archive = seekable(&entries, stored(features), extras()).unwrap();
    assert_eq!(archive, streamed(&entries, stored(features), extras()));
    rars::ArchiveReader::read(&archive)
        .unwrap()
        .test(None)
        .unwrap();
}

#![cfg(all(feature = "write", feature = "recovery"))]

use rars::{ArchiveReadOptions, ArchiveReader, ArchiveVersion, Builder};
use std::io::{self, Cursor, Read, Seek, SeekFrom};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

/// Remembers the largest single read asked of it.
struct Largest {
    input: Cursor<Vec<u8>>,
    largest: Arc<AtomicUsize>,
}

impl Read for Largest {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.largest.fetch_max(buffer.len(), Ordering::Relaxed);
        self.input.read(buffer)
    }
}

impl Seek for Largest {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        self.input.seek(from)
    }
}

fn markers(bytes: &[u8]) -> Vec<usize> {
    bytes
        .windows(4)
        .enumerate()
        .filter(|(_, window)| *window == b"{RB}")
        .map(|(at, _)| at)
        .collect()
}

/// A stored archive with a recovery record, then a copy with a run of its data
/// flipped and one recovery chunk broken, so repairing it rebuilds the record.
fn archive_with_a_lost_chunk() -> (Vec<u8>, Vec<u8>) {
    let payload: Vec<u8> = (0..600_000u32).map(|i| (i * 7 + (i >> 9)) as u8).collect();
    let mut builder = Builder::new(ArchiveVersion::Rar50)
        .store(true)
        .recovery_percent(Some(10));
    builder
        .add_bytes(b"file".to_vec(), payload, None, None)
        .unwrap();
    let original = builder.to_bytes().unwrap();
    let chunks = markers(&original);
    assert!(chunks.len() > 2);
    let mut damaged = original.clone();
    let data = original.len() / 3;
    assert!(data < chunks[0]);
    damaged[data..data + 64]
        .iter_mut()
        .for_each(|byte| *byte ^= 0xff);
    damaged[chunks[1] + 200] ^= 0xff;
    (original, damaged)
}

#[test]
fn a_record_that_lost_a_chunk_is_rebuilt_without_reading_the_archive_whole() {
    let (original, damaged) = archive_with_a_lost_chunk();
    let whole =
        rars::rar50::repair_inline_recovery_bytes_with_options(&damaged, ArchiveReadOptions::new())
            .unwrap();
    assert!(whole.report.data_repaired);
    assert!(whole.report.recovery_record_rebuilt);
    assert_eq!(whole.data, original);

    let largest = Arc::new(AtomicUsize::new(0));
    let archive = ArchiveReader::read_reader(Largest {
        input: Cursor::new(damaged.clone()),
        largest: largest.clone(),
    })
    .unwrap();
    largest.store(0, Ordering::Relaxed);
    let streamed = archive.repair_recovery_with_report(None).unwrap();
    assert_eq!(streamed, whole);
    assert!(
        largest.load(Ordering::Relaxed) < damaged.len() / 2,
        "read {} of {} bytes at once",
        largest.load(Ordering::Relaxed),
        damaged.len()
    );
}

#[test]
fn a_record_that_ends_the_archive_is_still_rebuilt_with_its_end_header() {
    // Cut after the recovery record: the end-of-archive header has to be
    // framed again, which the whole-archive repair does.
    let (_, damaged) = archive_with_a_lost_chunk();
    let end = damaged.len() - 8;
    let cut = &damaged[..end];
    let whole =
        rars::rar50::repair_inline_recovery_bytes_with_options(cut, ArchiveReadOptions::new())
            .unwrap();
    let archive = ArchiveReader::read(cut).unwrap();
    assert_eq!(archive.repair_recovery_with_report(None).unwrap(), whole);
}

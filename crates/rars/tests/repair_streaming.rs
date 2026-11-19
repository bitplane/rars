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

#[path = "support/scratch.rs"]
mod scratch;

fn with_damaged_header(mut archive: Vec<u8>) -> Vec<u8> {
    // Main-header CRC: only the raw recovery fallback can read it.
    archive[8] ^= 1;
    assert!(ArchiveReader::read(&archive).is_err());
    archive
}

#[test]
fn the_damaged_header_fallback_publishes_what_the_bytes_repair_returns() {
    let dir = scratch::case("raw-repair-to-path");
    let (original, lost_chunk) = archive_with_a_lost_chunk();
    let mut data_only = original.clone();
    let third = original.len() / 3;
    data_only[third..third + 64]
        .iter_mut()
        .for_each(|byte| *byte ^= 0xff);
    let cut = lost_chunk[..lost_chunk.len() - 8].to_vec();
    for (case, archive, streams) in [
        ("lost chunk", with_damaged_header(lost_chunk), true),
        ("whole record", with_damaged_header(data_only), true),
        ("ends at its record", with_damaged_header(cut), false),
    ] {
        let expected = rars::rar50::repair_inline_recovery_bytes_with_options(
            &archive,
            ArchiveReadOptions::new(),
        )
        .unwrap();
        let largest = Arc::new(AtomicUsize::new(0));
        let output = dir.join("repaired.rar");
        let report = rars::rar50::repair_inline_recovery_to_path_with_options(
            Largest {
                input: Cursor::new(archive.clone()),
                largest: largest.clone(),
            },
            &output,
            ArchiveReadOptions::new(),
        )
        .unwrap();
        assert_eq!(report, expected.report, "{case}");
        assert_eq!(std::fs::read(&output).unwrap(), expected.data, "{case}");
        let whole = largest.load(Ordering::Relaxed) >= archive.len();
        assert_eq!(whole, !streams, "{case}");
        assert_eq!(std::fs::read_dir(&*dir).unwrap().count(), 1, "{case}");
    }
}

#[test]
fn the_damaged_header_fallback_leaves_the_destination_alone_when_it_fails() {
    let dir = scratch::case("raw-repair-refusals");
    let (_, damaged) = archive_with_a_lost_chunk();
    let archive = with_damaged_header(damaged);
    let output = dir.join("existing.rar");
    std::fs::write(&output, b"keep").unwrap();

    let token = rars::ReadCancellation::new();
    token.cancel();
    let cancelled = rars::rar50::repair_inline_recovery_to_path_with_options(
        Cursor::new(archive.clone()),
        &output,
        ArchiveReadOptions::new().with_cancellation(&token),
    );
    assert_eq!(cancelled.unwrap_err().kind(), rars::ErrorKind::Cancelled);
    let not_rar5 = rars::rar50::repair_inline_recovery_to_path_with_options(
        Cursor::new(b"not an archive at all".to_vec()),
        &output,
        ArchiveReadOptions::new(),
    );
    assert!(not_rar5.is_err());

    assert_eq!(std::fs::read(&output).unwrap(), b"keep");
    assert_eq!(std::fs::read_dir(&*dir).unwrap().count(), 1);
}

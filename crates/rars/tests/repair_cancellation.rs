#![cfg(all(feature = "write", feature = "recovery"))]

use rars::{
    ArchiveReadOptions, ArchiveReader, ArchiveVersion, Builder, ErrorKind, ReadCancellation,
};
use std::{
    io::{self, Cursor, Read, Seek, SeekFrom},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

#[path = "support/scratch.rs"]
mod scratch;

struct CancelOnRead {
    input: Cursor<Vec<u8>>,
    armed: Arc<AtomicBool>,
    token: ReadCancellation,
}
impl Read for CancelOnRead {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.armed.load(Ordering::Relaxed) {
            self.token.cancel();
        }
        self.input.read(buffer)
    }
}
impl Seek for CancelOnRead {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        self.input.seek(from)
    }
}

#[test]
fn cancellation_during_recovery_source_reads_survives_each_format_adapter() {
    for version in [
        ArchiveVersion::Rar20,
        ArchiveVersion::Rar40,
        ArchiveVersion::Rar50,
    ] {
        let mut builder = Builder::new(version).store(true).recovery_percent(Some(10));
        builder
            .add_bytes(b"file".to_vec(), vec![42; 20_000], None, None)
            .unwrap();
        let bytes = match version {
            ArchiveVersion::Rar20 => {
                include_bytes!("fixtures/rar15_40/rar250_protect_head_rr5.rar").to_vec()
            }
            ArchiveVersion::Rar40 => {
                include_bytes!("fixtures/rar15_40/rar300/with_compressed_recovery_rar300.rar")
                    .to_vec()
            }
            _ => builder.to_bytes().unwrap(),
        };
        let token = ReadCancellation::new();
        let armed = Arc::new(AtomicBool::new(false));
        let archive = ArchiveReader::read_reader(CancelOnRead {
            input: Cursor::new(bytes),
            armed: armed.clone(),
            token: token.clone(),
        })
        .unwrap();
        armed.store(true, Ordering::Relaxed);
        let options = ArchiveReadOptions::new().with_cancellation(&token);
        assert_eq!(
            archive
                .repair_recovery_with_options(options)
                .unwrap_err()
                .kind(),
            ErrorKind::Cancelled
        );
        armed.store(false, Ordering::Relaxed);
        let repaired = archive.repair_recovery_with_report(None).unwrap();
        assert!(!repaired.report.changed);
    }
}

#[test]
fn failed_or_cancelled_publication_keeps_the_destination_and_removes_staging() {
    let dir = scratch::case("repair-publication");
    let result = rars::RecoveryRepairResult {
        data: b"repaired".to_vec(),
        report: Default::default(),
    };
    let path = dir.join("existing");
    std::fs::write(&path, b"keep").unwrap();
    let token = ReadCancellation::new();
    token.cancel();
    assert_eq!(
        result
            .write_to_path(&path, Some(&token))
            .unwrap_err()
            .kind(),
        ErrorKind::Cancelled
    );
    assert_eq!(std::fs::read(&path).unwrap(), b"keep");
    let directory = dir.join("directory");
    std::fs::create_dir(&directory).unwrap();
    assert!(result.write_to_path(&directory, None).is_err());
    assert!(directory.is_dir());
    assert_eq!(std::fs::read_dir(&*dir).unwrap().count(), 2);
    result.write_to_path(&path, None).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"repaired");
    assert_eq!(std::fs::read_dir(&*dir).unwrap().count(), 2);
}

#[test]
fn repairing_to_a_path_publishes_what_the_repair_returns_and_nothing_else() {
    let dir = scratch::case("repair-to-path");
    let mut builder = Builder::new(ArchiveVersion::Rar50)
        .store(true)
        .recovery_percent(Some(10));
    builder
        .add_bytes(b"file".to_vec(), vec![42; 200_000], None, None)
        .unwrap();
    let mut damaged = builder.to_bytes().unwrap();
    let middle = damaged.len() / 2;
    damaged[middle..middle + 64]
        .iter_mut()
        .for_each(|byte| *byte ^= 0xff);
    for archive_bytes in [
        include_bytes!("fixtures/rar15_40/rar250_protect_head_rr5.rar").to_vec(),
        include_bytes!("fixtures/rar15_40/rar300/with_compressed_recovery_rar300.rar").to_vec(),
        damaged,
    ] {
        let source = dir.join("source.rar");
        std::fs::write(&source, &archive_bytes).unwrap();
        let archive = ArchiveReader::read_path(&source).unwrap();
        let expected = archive.repair_recovery_with_report(None).unwrap();

        let output = dir.join("output.rar");
        std::fs::write(&output, b"keep").unwrap();
        let token = ReadCancellation::new();
        token.cancel();
        let cancelled = ArchiveReadOptions::new().with_cancellation(&token);
        let error = archive
            .repair_recovery_to_path_with_options(&output, cancelled)
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Cancelled);
        assert_eq!(std::fs::read(&output).unwrap(), b"keep");
        assert_eq!(std::fs::read_dir(&*dir).unwrap().count(), 2);

        let report = archive
            .repair_recovery_to_path_with_options(&output, ArchiveReadOptions::new())
            .unwrap();
        assert_eq!(report, expected.report);
        assert_eq!(std::fs::read(&output).unwrap(), expected.data);
        assert_eq!(std::fs::read_dir(&*dir).unwrap().count(), 2);

        // Over its own source, which is read until the repaired copy replaces it.
        archive
            .repair_recovery_to_path_with_options(&source, ArchiveReadOptions::new())
            .unwrap();
        assert_eq!(std::fs::read(&source).unwrap(), expected.data);
        std::fs::remove_file(&output).unwrap();
    }
}

#![cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
#[path = "support/scratch.rs"]
mod scratch;
use rars::rar50::{ArchiveEntry, Rar50Writer, WriterOptions};
use rars::{
    Archive, ArchiveReadOptions, ArchiveReader, ArchiveVersion, EntrySource, Error, FeatureSet,
    FilterKind, FilterPolicy, Rar50Scratch,
};
use std::{cell::RefCell, io, io::Write, rc::Rc, sync::Arc};

struct Capture(Rc<RefCell<Vec<u8>>>);
impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.borrow_mut().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn payload() -> Vec<u8> {
    (0..196_608)
        .map(|i| [0xe8, 1, 0, 0, 0, 0xe9, 3, 0, 0, 0, 0xeb, 0x14][i % 12])
        .collect()
}
fn entry(data: &[u8], encrypted: bool) -> ArchiveEntry {
    let entry = ArchiveEntry::new(
        b"file".to_vec(),
        EntrySource::from_bytes(Arc::<[u8]>::from(data.to_vec())),
    );
    if encrypted {
        entry.with_password(b"secret".to_vec())
    } else {
        entry
    }
}
fn options(version: ArchiveVersion) -> WriterOptions {
    WriterOptions::new(version, FeatureSet::store_only())
}
fn archive(kind: FilterKind, encrypted: bool, version: ArchiveVersion) -> Archive {
    ArchiveReader::read_owned(
        Rar50Writer::new(options(version))
            .entries([entry(&payload(), encrypted)])
            .filter_policy(FilterPolicy::explicit(kind))
            .finish()
            .unwrap(),
    )
    .unwrap()
}

#[test]
fn disk_scratch_handles_all_filters_encryption_and_parallel_entry_points() {
    let dir = scratch::case("reader-scratch-filters");
    let policy = Rar50Scratch::new(&*dir, 1_000_000).with_filter_memory_limit(128 * 1024);
    for version in [ArchiveVersion::Rar50, ArchiveVersion::Rar70] {
        for kind in [
            FilterKind::E8,
            FilterKind::E8E9,
            FilterKind::Arm,
            FilterKind::Delta { channels: 3 },
        ] {
            for encrypted in [false, true] {
                let archive = archive(kind, encrypted, version);
                let mut options = ArchiveReadOptions::new()
                    .with_rar50_buffered_decode_limit(1024)
                    .with_rar50_scratch(&policy);
                options.password = encrypted.then_some(b"secret");
                let output = Rc::new(RefCell::new(Vec::new()));
                archive
                    .extract_to_parallel_buffered_with_options(options, |_| {
                        Ok(Box::new(Capture(output.clone())))
                    })
                    .unwrap();
                assert_eq!(*output.borrow(), payload());
                assert_eq!(std::fs::read_dir(&*dir).unwrap().count(), 0);
            }
        }
    }
}

#[test]
fn scratch_and_filter_limits_refuse_before_publication_and_clean_up() {
    let dir = scratch::case("reader-scratch-limits");
    let archive = archive(FilterKind::E8, false, ArchiveVersion::Rar50);
    for (disk, memory, filter_error) in [
        (1000, 131072, false),
        (1_000_000, 1024, true),
        (393216, 131072, false),
    ] {
        let policy = Rar50Scratch::new(&*dir, disk).with_filter_memory_limit(memory);
        let output = Rc::new(RefCell::new(Vec::new()));
        let error = archive
            .extract_to_with_options(
                ArchiveReadOptions::new()
                    .with_rar50_buffered_decode_limit(1024)
                    .with_rar50_scratch(&policy),
                |_| Ok(Box::new(Capture(output.clone()))),
            )
            .unwrap_err();
        assert_eq!(error.kind(), rars::ErrorKind::ResourceLimit);
        assert!(if filter_error {
            matches!(
                error.root_cause(),
                Error::Rar50FilterMemoryLimitExceeded { .. }
            )
        } else {
            matches!(error.root_cause(), Error::Rar50ScratchLimitExceeded { .. })
        });
        assert!(output.borrow().is_empty());
        assert_eq!(std::fs::read_dir(&*dir).unwrap().count(), 0);
    }
}

#[test]
fn integrity_and_sink_failures_release_scratch() {
    let dir = scratch::case("reader-scratch-failures");
    let policy = Rar50Scratch::new(&*dir, 1_000_000);
    let mut archive = archive(
        FilterKind::Delta { channels: 3 },
        false,
        ArchiveVersion::Rar50,
    );
    let options = ArchiveReadOptions::new()
        .with_rar50_buffered_decode_limit(1024)
        .with_rar50_scratch(&policy);
    struct Broken;
    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::ErrorKind::PermissionDenied.into())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let error = archive
        .extract_to_with_options(options, |_| Ok(Box::new(Broken)))
        .unwrap_err();
    assert_eq!(error.kind(), rars::ErrorKind::Io);
    assert_eq!(std::fs::read_dir(&*dir).unwrap().count(), 0);
    if let Archive::Rar50Plus(a) = &mut archive {
        for block in &mut a.blocks {
            if let rars::rar50::Block::File(file) = block {
                file.hash = None;
                file.data_crc32 = Some(0);
            }
        }
    }
    let output = Rc::new(RefCell::new(Vec::new()));
    let error = archive
        .extract_to_with_options(options, |_| Ok(Box::new(Capture(output.clone()))))
        .unwrap_err();
    assert_eq!(error.kind(), rars::ErrorKind::ChecksumMismatch);
    assert!(output.borrow().is_empty());
    assert_eq!(std::fs::read_dir(&*dir).unwrap().count(), 0);
}

#[test]
fn split_filtered_members_use_scratch_and_keep_limit_errors() {
    let dir = scratch::case("reader-scratch-split");
    for encrypted in [false, true] {
        let mut sink = rars::rar50::CollectedVolumes::new();
        rars::rar50::write_streaming_volumes_to(
            &[entry(&payload(), encrypted)],
            options(ArchiveVersion::Rar50),
            rars::rar50::ArchiveExtras::default()
                .with_filter_policy(FilterPolicy::explicit(FilterKind::E8)),
            64,
            &mut sink,
            &rars::WriterResources::default().with_temp_dir(&*dir),
        )
        .unwrap();
        let volumes: Vec<_> = sink
            .take()
            .into_iter()
            .map(|bytes| ArchiveReader::read_owned(bytes).unwrap())
            .collect();
        assert!(volumes.len() > 1);
        for disk in [1_000_000, 100] {
            let policy = Rar50Scratch::new(&*dir, disk);
            let mut options = ArchiveReadOptions::new()
                .with_rar50_buffered_decode_limit(1024)
                .with_rar50_scratch(&policy);
            options.password = encrypted.then_some(b"secret");
            let output = Rc::new(RefCell::new(Vec::new()));
            let result = rars::extract_volumes_to_with_options(&volumes, options, |_| {
                Ok(Box::new(Capture(output.clone())))
            });
            if disk == 100 {
                assert!(matches!(
                    result.unwrap_err().root_cause(),
                    Error::Rar50ScratchLimitExceeded { .. }
                ));
                assert!(output.borrow().is_empty());
            } else {
                result.unwrap();
                assert_eq!(*output.borrow(), payload());
            }
            assert_eq!(std::fs::read_dir(&*dir).unwrap().count(), 0);
        }
    }
}

#[test]
fn publication_cancellation_cleans_up_scratch() {
    let dir = scratch::case("reader-scratch-cancel");
    let policy = Rar50Scratch::new(&*dir, 1_000_000);
    let token = rars::ReadCancellation::new();
    struct Cancel(rars::ReadCancellation);
    impl Write for Cancel {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.cancel();
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let archive = archive(FilterKind::E8, false, ArchiveVersion::Rar50);
    let error = archive
        .extract_to_with_options(
            ArchiveReadOptions::new()
                .with_cancellation(&token)
                .with_rar50_buffered_decode_limit(1024)
                .with_rar50_scratch(&policy),
            |_| Ok(Box::new(Cancel(token.clone()))),
        )
        .unwrap_err();
    assert_eq!(error.kind(), rars::ErrorKind::Cancelled);
    assert_eq!(std::fs::read_dir(&*dir).unwrap().count(), 0);
}

#[test]
fn scratch_preserves_the_raw_lz_integrity_fallback() {
    let dir = scratch::case("reader-scratch-fallback");
    let policy = Rar50Scratch::new(&*dir, 1_000_000);
    let mut archive = archive(FilterKind::E8, false, ArchiveVersion::Rar50);
    let Archive::Rar50Plus(a) = &mut archive else {
        unreachable!()
    };
    let file = a.files().next().unwrap();
    let info = file.decoded_compression_info().unwrap();
    let raw = rars::codec::rar50::Unpack50Decoder::new()
        .decode_member_with_dictionary(
            &file.packed_data(a).unwrap(),
            info.algorithm_version,
            payload().len(),
            info.dictionary_size as usize,
            false,
            rars::codec::rar50::DecodeMode::LzNoFilters,
        )
        .unwrap();
    assert_ne!(raw, payload());
    for block in &mut a.blocks {
        if let rars::rar50::Block::File(file) = block {
            file.hash = None;
            file.data_crc32 = Some(rars::crc32::crc32(&raw));
        }
    }
    for scratch in [false, true] {
        let mut options = ArchiveReadOptions::new();
        if scratch {
            options = options
                .with_rar50_buffered_decode_limit(1024)
                .with_rar50_scratch(&policy);
        }
        let output = Rc::new(RefCell::new(Vec::new()));
        archive
            .extract_to_with_options(options, |_| Ok(Box::new(Capture(output.clone()))))
            .unwrap();
        assert_eq!(*output.borrow(), raw);
        assert_eq!(std::fs::read_dir(&*dir).unwrap().count(), 0);
    }
}

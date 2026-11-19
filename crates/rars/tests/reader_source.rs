#![cfg(feature = "write")]

use rars::{ArchiveReadOptions, ArchiveReader, ArchiveVersion, Builder};
#[path = "support/scratch.rs"]
mod scratch;
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, Mutex,
};

struct Tracked {
    data: Cursor<Vec<u8>>,
    reads: Arc<AtomicUsize>,
    dropped: Arc<AtomicBool>,
    fail: Arc<AtomicBool>,
}
impl Read for Tracked {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if self.fail.load(Ordering::Relaxed) {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        // Exercise repeated short reads through signature/header/payload adapters.
        let len = bytes.len().min(137);
        let count = self.data.read(&mut bytes[..len])?;
        self.reads.fetch_add(count, Ordering::Relaxed);
        Ok(count)
    }
}
impl Seek for Tracked {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        self.data.seek(from)
    }
}
impl Drop for Tracked {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::Relaxed);
    }
}
fn tracked(bytes: Vec<u8>) -> Tracked {
    let mut data = Cursor::new(bytes);
    data.set_position(19);
    Tracked {
        data,
        reads: Arc::default(),
        dropped: Arc::default(),
        fail: Arc::default(),
    }
}
struct Capture(Arc<Mutex<Vec<u8>>>);
impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn seekable_sources_cover_families_encryption_sfx_and_parallel_extraction() {
    for version in [
        ArchiveVersion::Rar14,
        ArchiveVersion::Rar15,
        ArchiveVersion::Rar20,
        ArchiveVersion::Rar29,
        ArchiveVersion::Rar30,
        ArchiveVersion::Rar40,
        ArchiveVersion::Rar50,
        ArchiveVersion::Rar70,
    ] {
        // Plain archives run too: an unencrypted RAR 5 archive behind a prefix
        // once failed only on this path. RAR 1.4 cannot encrypt.
        for (stored, encrypted) in [(true, false), (false, false), (true, true), (false, true)] {
            if encrypted && (version == ArchiveVersion::Rar14 || !cfg!(feature = "encryption")) {
                continue;
            }
            let password = encrypted.then_some(b"secret".as_slice());
            let mut builder = Builder::new(version)
                .store(stored)
                .password(password.map(Vec::from))
                .header_encryption(
                    encrypted
                        && matches!(
                            version,
                            ArchiveVersion::Rar30
                                | ArchiveVersion::Rar40
                                | ArchiveVersion::Rar50
                                | ArchiveVersion::Rar70
                        ),
                );
            let mut expected = Vec::new();
            for index in 0..4 {
                let data = vec![index as u8; 2048 + index];
                expected.extend_from_slice(&data);
                builder
                    .add_bytes(index.to_string().into_bytes(), data, None, None)
                    .unwrap();
            }
            let mut bytes = vec![0; 31];
            bytes.extend(builder.to_bytes().unwrap());
            let mut options = ArchiveReadOptions::new();
            options.password = password;
            let parsed = ArchiveReader::read_with_options(&bytes, options).unwrap();
            let source = tracked(bytes);
            let dropped = source.dropped.clone();
            let archive = ArchiveReader::read_reader_with_options(source, options).unwrap();
            // Both parsers bound the walk by where the archive ends, so they
            // agree on what a rewrite would lose.
            assert_eq!(
                archive.rewrite_preservation_issues(),
                parsed.rewrite_preservation_issues(),
                "{version:?} stored={stored} encrypted={encrypted}"
            );
            let clone = archive.clone();
            drop(archive);
            assert!(!dropped.load(Ordering::Relaxed));
            for parallel in [false, true] {
                let output = Arc::new(Mutex::new(Vec::new()));
                let open = |_: &rars::ExtractedEntryMeta| {
                    Ok(Box::new(Capture(output.clone())) as Box<dyn Write>)
                };
                if parallel {
                    clone.extract_to_parallel_buffered(password, open).unwrap();
                } else {
                    clone.extract_to(password, open).unwrap();
                }
                assert_eq!(*output.lock().unwrap(), expected);
            }
            drop(clone);
            assert!(dropped.load(Ordering::Relaxed));
        }
    }
}

#[test]
fn unencrypted_rar5_behind_a_prefix_reads_as_the_byte_parser_does() {
    // Comment, quick-open locator and recovery record all sit at offsets the
    // seekable parser has to place past the prefix.
    for version in [ArchiveVersion::Rar50, ArchiveVersion::Rar70] {
        for stored in [true, false] {
            for prefix in [1, 7, 31, 4096] {
                let mut builder = Builder::new(version)
                    .store(stored)
                    .comment(Some(b"archive comment".to_vec()))
                    .recovery_percent(cfg!(feature = "recovery").then_some(5))
                    .archive_metadata(None, false, true)
                    .unwrap();
                for index in 0..4 {
                    builder
                        .add_bytes(
                            index.to_string().into_bytes(),
                            vec![index as u8; 2048 + index],
                            None,
                            None,
                        )
                        .unwrap();
                }
                let mut bytes = vec![0; prefix];
                bytes.extend(builder.to_bytes().unwrap());
                let case = format!("{version:?} stored={stored} prefix={prefix}");
                let expected = ArchiveReader::read(&bytes).unwrap();
                let archive = ArchiveReader::read_reader(tracked(bytes.clone()))
                    .unwrap_or_else(|error| panic!("{case}: {error:?}"));

                assert_eq!(archive.sfx_offset(), prefix, "{case}");
                assert_eq!(
                    archive.members().collect::<Vec<_>>(),
                    expected.members().collect::<Vec<_>>(),
                    "{case}"
                );
                assert_eq!(
                    archive.comment(None).unwrap().as_deref(),
                    Some(b"archive comment".as_slice()),
                    "{case}"
                );
                archive.test(None).unwrap();
                assert_eq!(
                    archive.read_member(b"2", None).unwrap().unwrap(),
                    vec![2; 2050],
                    "{case}"
                );
                let extracted = |archive: &rars::Archive| {
                    let output = Arc::new(Mutex::new(Vec::new()));
                    archive
                        .extract_to(None, |_| Ok(Box::new(Capture(output.clone()))))
                        .unwrap();
                    let output = output.lock().unwrap().clone();
                    output
                };
                assert_eq!(extracted(&archive), extracted(&expected), "{case}");
                if cfg!(feature = "recovery") {
                    // The record protects the archive past the prefix, and an
                    // intact one repairs to the same bytes.
                    assert_eq!(archive.repair_recovery().unwrap(), bytes, "{case}");
                    assert_eq!(expected.repair_recovery().unwrap(), bytes, "{case}");
                }
            }
        }
    }
}

#[test]
fn parsing_skips_large_payloads_and_keeps_the_source_for_later_reads() {
    for version in [
        ArchiveVersion::Rar14,
        ArchiveVersion::Rar29,
        ArchiveVersion::Rar50,
    ] {
        let data = vec![42; rars::SFX_SCAN_LIMIT * 2];
        let mut builder = Builder::new(version).store(true);
        builder
            .add_bytes(b"file".to_vec(), data.clone(), None, None)
            .unwrap();
        let source = tracked(builder.to_bytes().unwrap());
        let reads = source.reads.clone();
        let fail = source.fail.clone();
        let archive = ArchiveReader::read_reader(source).unwrap();
        assert!(reads.load(Ordering::Relaxed) < data.len());
        if version != ArchiveVersion::Rar14 {
            assert!(
                reads.load(Ordering::Relaxed) < 1024,
                "standard strong-signature parsing reads headers, not the payload scan"
            );
        }
        assert_eq!(archive.read_member(b"file", None).unwrap().unwrap(), data);
        fail.store(true, Ordering::Relaxed);
        let error = archive
            .extract_to(None, |_| Ok(Box::new(io::sink())))
            .unwrap_err();
        assert_eq!(error.kind(), rars::ErrorKind::Io);
    }
}

#[test]
fn caller_sources_observe_parse_limits_and_precancellation() {
    let mut builder = Builder::new(ArchiveVersion::Rar50).store(true);
    builder
        .add_bytes(b"file".to_vec(), vec![42; 128], None, None)
        .unwrap();
    let bytes = builder.to_bytes().unwrap();
    let error = ArchiveReader::read_reader_with_options(
        Cursor::new(bytes.clone()),
        ArchiveReadOptions::new().with_max_header_count(0),
    )
    .unwrap_err();
    assert_eq!(error.kind(), rars::ErrorKind::ResourceLimit);
    let source = tracked(bytes);
    let reads = source.reads.clone();
    let token = rars::ReadCancellation::new();
    token.cancel();
    let error = ArchiveReader::read_reader_with_options(
        source,
        ArchiveReadOptions::new().with_cancellation(&token),
    )
    .unwrap_err();
    assert_eq!(error.kind(), rars::ErrorKind::Cancelled);
    assert_eq!(reads.load(Ordering::Relaxed), 0);
}

#[test]
fn split_members_can_read_from_multiple_caller_owned_sources() {
    for version in [
        ArchiveVersion::Rar14,
        ArchiveVersion::Rar29,
        ArchiveVersion::Rar50,
    ] {
        let mut builder = Builder::new(version).store(true).volume_size(Some(512));
        let data = vec![42; 2048];
        builder
            .add_bytes(b"file".to_vec(), data.clone(), None, None)
            .unwrap();
        let volumes: Vec<_> = builder
            .build_volumes(None)
            .unwrap()
            .into_iter()
            .enumerate()
            .map(|(index, volume)| {
                // An SFX stub sits in front of the first volume only.
                let mut bytes = vec![0; if index == 0 { 31 } else { 0 }];
                bytes.extend(volume);
                ArchiveReader::read_reader(tracked(bytes)).unwrap()
            })
            .collect();
        assert!(volumes.len() > 1);
        let output = Arc::new(Mutex::new(Vec::new()));
        rars::extract_volumes_to(&volumes, None, |_| Ok(Box::new(Capture(output.clone()))))
            .unwrap();
        assert_eq!(*output.lock().unwrap(), data);
    }
}

#[cfg(unix)]
#[test]
fn owned_file_handle_remains_usable_after_its_path_is_removed() {
    let dir = scratch::case("reader-owned-file");
    let path = dir.join("archive.rar");
    let mut builder = Builder::new(ArchiveVersion::Rar50).store(true);
    builder
        .add_bytes(b"file".to_vec(), b"payload".to_vec(), None, None)
        .unwrap();
    std::fs::write(&path, builder.to_bytes().unwrap()).unwrap();
    let archive = ArchiveReader::read_reader(std::fs::File::open(&path).unwrap()).unwrap();
    std::fs::remove_file(path).unwrap();
    assert_eq!(
        archive.read_member(b"file", None).unwrap().unwrap(),
        b"payload"
    );
}

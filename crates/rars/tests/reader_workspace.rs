use rars::{ArchiveReadOptions, ArchiveReader, ArchiveVersion, Builder, ErrorKind};
use std::{cell::RefCell, io::Write, rc::Rc};

struct Capture(Rc<RefCell<Vec<u8>>>);
impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.borrow_mut().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn workspace_policy_covers_every_codec_and_parallel_publication() {
    for version in [
        ArchiveVersion::Rar13,
        ArchiveVersion::Rar15,
        ArchiveVersion::Rar20,
        ArchiveVersion::Rar29,
        ArchiveVersion::Rar50,
        ArchiveVersion::Rar70,
    ] {
        let data = b"reader workspace accounting".repeat(64);
        let mut builder = Builder::new(version).store(false);
        for name in [b"first".to_vec(), b"second".to_vec()] {
            builder.add_bytes(name, data.clone(), None, None).unwrap();
        }
        let archive = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
        for parallel in [false, true] {
            for limit in [1, 64 << 20] {
                let output = Rc::new(RefCell::new(Vec::new()));
                let options = ArchiveReadOptions::new().with_max_reader_workspace_bytes(limit);
                let open = |_: &rars::ExtractedEntryMeta| {
                    Ok(Box::new(Capture(output.clone())) as Box<dyn Write>)
                };
                let result = if parallel {
                    archive.extract_to_parallel_buffered_with_options(options, open)
                } else {
                    archive.extract_to_with_options(options, open)
                };
                if limit == 1 {
                    assert_eq!(
                        result.unwrap_err().kind(),
                        ErrorKind::ResourceLimit,
                        "{version:?}"
                    );
                    assert!(output.borrow().is_empty());
                } else {
                    result.unwrap();
                    assert_eq!(*output.borrow(), data.repeat(2), "{version:?}");
                }
            }
        }
    }
}

#[test]
fn stored_sequential_payloads_do_not_require_a_dictionary() {
    for version in [
        ArchiveVersion::Rar13,
        ArchiveVersion::Rar20,
        ArchiveVersion::Rar50,
    ] {
        let mut builder = Builder::new(version).store(true);
        builder
            .add_bytes(b"file".to_vec(), vec![42; 1024], None, None)
            .unwrap();
        let archive = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
        archive
            .extract_to_with_options(
                ArchiveReadOptions::new().with_max_reader_workspace_bytes(0),
                |_| Ok(Box::new(std::io::sink())),
            )
            .unwrap();
    }
}

#[test]
fn limited_parallel_legacy_extraction_handles_directories_and_stored_files() {
    for version in [ArchiveVersion::Rar15, ArchiveVersion::Rar29] {
        let mut builder = Builder::new(version).store(true);
        builder.add_directory(b"dir".to_vec(), None, None).unwrap();
        builder
            .add_bytes(b"file".to_vec(), b"payload".to_vec(), None, None)
            .unwrap();
        let archive = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
        let output = Rc::new(RefCell::new(Vec::new()));
        let mut seen = Vec::new();
        archive
            .extract_to_parallel_buffered_with_options(
                ArchiveReadOptions::new().with_max_reader_workspace_bytes(1 << 20),
                |meta| {
                    seen.push((meta.name.clone(), meta.is_directory));
                    Ok(Box::new(Capture(output.clone())) as Box<dyn Write>)
                },
            )
            .unwrap();
        assert_eq!(seen, [(b"dir".to_vec(), true), (b"file".to_vec(), false)]);
        assert_eq!(*output.borrow(), b"payload");
    }
}

#[test]
fn workspace_refusal_is_not_remapped_to_a_password_or_integrity_failure() {
    for version in [
        ArchiveVersion::Rar13,
        ArchiveVersion::Rar15,
        ArchiveVersion::Rar20,
        ArchiveVersion::Rar29,
        ArchiveVersion::Rar50,
    ] {
        let mut builder = Builder::new(version)
            .store(false)
            .password(Some(b"pw".to_vec()));
        builder
            .add_bytes(
                b"file".to_vec(),
                b"encrypted payload".repeat(32),
                None,
                None,
            )
            .unwrap();
        let archive = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
        for limit in [1, 64 << 20] {
            let options =
                ArchiveReadOptions::with_password(b"pw").with_max_reader_workspace_bytes(limit);
            let result =
                archive.extract_to_with_options(options, |_| Ok(Box::new(std::io::sink())));
            if limit == 1 {
                assert_eq!(
                    result.unwrap_err().kind(),
                    ErrorKind::ResourceLimit,
                    "{version:?}"
                );
            } else {
                result.unwrap();
            }
        }
    }
}

#[test]
fn workspace_policy_applies_to_compressed_comments_without_changing_their_checksums() {
    let comment = b"compressed archive comment".repeat(32);
    for version in [
        ArchiveVersion::Rar13,
        ArchiveVersion::Rar15,
        ArchiveVersion::Rar20,
        ArchiveVersion::Rar29,
        ArchiveVersion::Rar50,
    ] {
        let mut builder = Builder::new(version)
            .store(false)
            .comment(Some(comment.clone()));
        builder
            .add_bytes(b"file".to_vec(), vec![42; 256], None, None)
            .unwrap();
        let archive = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
        let actual = archive
            .comment_with_options(
                ArchiveReadOptions::new().with_max_reader_workspace_bytes(64 << 20),
            )
            .unwrap();
        assert_eq!(actual.as_deref(), Some(&comment[..]), "{version:?}");
        let error = archive
            .comment_with_options(ArchiveReadOptions::new().with_max_reader_workspace_bytes(1))
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::ResourceLimit, "{version:?}");
    }
}

#[test]
fn split_descriptor_and_cursor_accounting_is_shared_across_volumes() {
    for version in [
        ArchiveVersion::Rar13,
        ArchiveVersion::Rar20,
        ArchiveVersion::Rar50,
    ] {
        let mut builder = Builder::new(version).store(true).volume_size(Some(512));
        let data: Vec<_> = (0..2048).map(|i| i as u8).collect();
        builder
            .add_bytes(b"file".to_vec(), data.clone(), None, None)
            .unwrap();
        let volumes: Vec<_> = builder
            .build_volumes(None)
            .unwrap()
            .into_iter()
            .map(|bytes| ArchiveReader::read_owned(bytes).unwrap())
            .collect();
        assert!(volumes.len() > 1);
        for limit in [1, 64 << 20] {
            let output = Rc::new(RefCell::new(Vec::new()));
            let result = rars::extract_volumes_to_with_options(
                &volumes,
                ArchiveReadOptions::new().with_max_reader_workspace_bytes(limit),
                |_| Ok(Box::new(Capture(output.clone()))),
            );
            if limit == 1 {
                assert_eq!(
                    result.unwrap_err().kind(),
                    ErrorKind::ResourceLimit,
                    "{version:?}"
                );
                assert!(output.borrow().is_empty());
            } else {
                result.unwrap();
                assert_eq!(*output.borrow(), data);
            }
        }
    }
}

#[test]
fn historical_audio_vm_ppmd_and_solid_archives_decode_under_the_policy() {
    for bytes in [
        &include_bytes!("fixtures/rar13/BIG80K.RAR")[..],
        &include_bytes!("fixtures/rar15_40/rar250/AUDIO.RAR")[..],
        &include_bytes!("fixtures/rar15_40/rar250/SOLID.RAR")[..],
        &include_bytes!("fixtures/rar15_40/rar300/rarvm_audio_stereo_rar300.rar")[..],
        &include_bytes!("fixtures/rar15_40/ppmd/ppmd_solid_rar300.rar")[..],
    ] {
        let archive = ArchiveReader::read(bytes).unwrap();
        let expected = Rc::new(RefCell::new(Vec::new()));
        archive
            .extract_to_with_options(ArchiveReadOptions::new(), |_| {
                Ok(Box::new(Capture(expected.clone())))
            })
            .unwrap();
        let actual = Rc::new(RefCell::new(Vec::new()));
        archive
            .extract_to_with_options(
                ArchiveReadOptions::new().with_max_reader_workspace_bytes(64 << 20),
                |_| Ok(Box::new(Capture(actual.clone()))),
            )
            .unwrap();
        assert_eq!(*actual.borrow(), *expected.borrow());
    }
}

#[test]
fn solid_rar5_streaming_and_selected_reads_share_the_operation_quota() {
    let data = b"solid workspace payload".repeat(128);
    let mut builder = Builder::new(ArchiveVersion::Rar50).store(false).solid(true);
    for name in [b"first".to_vec(), b"second".to_vec()] {
        builder.add_bytes(name, data.clone(), None, None).unwrap();
    }
    let archive = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
    for limit in [1, 64 << 20] {
        let options = ArchiveReadOptions::new()
            .with_max_reader_workspace_bytes(limit)
            .with_rar50_buffered_decode_limit(0);
        let result = archive.read_member_with_options(b"second", options);
        if limit == 1 {
            assert_eq!(result.unwrap_err().kind(), ErrorKind::ResourceLimit);
        } else {
            assert_eq!(result.unwrap(), Some(data.clone()));
        }
    }
}

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
#[path = "support/scratch.rs"]
mod scratch;

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
#[test]
fn scratch_filter_allocations_obey_the_shared_quota_and_clean_up() {
    use rars::rar50::{ArchiveEntry, Rar50Writer, WriterOptions};
    use rars::{EntrySource, FeatureSet, FilterKind, FilterPolicy, FilterSpec, Rar50Scratch};
    let data = b"Delta scratch workspace".repeat(64);
    let bytes = Rar50Writer::new(
        WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only())
            .with_compression_level(1),
    )
    .entry(ArchiveEntry::new(
        b"file".to_vec(),
        EntrySource::from_bytes(data.clone()),
    ))
    .filter_policy(FilterPolicy::Explicit(FilterSpec::whole(
        FilterKind::Delta { channels: 2 },
    )))
    .finish()
    .unwrap();
    let archive = ArchiveReader::read_owned(bytes).unwrap();
    let dir = scratch::case("reader-workspace-public-scratch");
    let policy = Rar50Scratch::new(&*dir, 65536);
    for limit in [1, 64 << 20] {
        let output = Rc::new(RefCell::new(Vec::new()));
        let options = ArchiveReadOptions::new()
            .with_max_reader_workspace_bytes(limit)
            .with_rar50_buffered_decode_limit(1)
            .with_rar50_scratch(&policy);
        let result = archive.extract_to_parallel_buffered_with_options(options, |_| {
            Ok(Box::new(Capture(output.clone())))
        });
        if limit == 1 {
            assert_eq!(result.unwrap_err().kind(), ErrorKind::ResourceLimit);
            assert!(output.borrow().is_empty());
        } else {
            result.unwrap();
            assert_eq!(*output.borrow(), data);
        }
        assert_eq!(std::fs::read_dir(&*dir).unwrap().count(), 0);
    }
}

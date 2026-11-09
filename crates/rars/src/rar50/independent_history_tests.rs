use super::super::{ArchiveEntry, Block, FilterKind, FilterPolicy, Rar50Writer, WriterOptions};
use super::*;
use crate::{ArchiveVersion, FeatureSet};
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;

type ExtractedFiles = Vec<(Vec<u8>, Vec<u8>)>;

fn entry(name: &[u8], data: &[u8]) -> ArchiveEntry {
    ArchiveEntry::new(
        name.to_vec(),
        crate::EntrySource::from_bytes(Arc::<[u8]>::from(data.to_vec())),
    )
}
#[derive(Clone)]
struct Sink(Rc<RefCell<Vec<u8>>>);
impl Write for Sink {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.0.borrow_mut().extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn archive(version: ArchiveVersion, filter: Option<FilterKind>) -> (Archive, Vec<u8>) {
    let data = b"independent buffered dictionary filter member repeated bytes\n".repeat(64);
    let mut writer = Rar50Writer::new(
        WriterOptions::new(version, FeatureSet::store_only())
            .with_compression_level(1)
            .with_dictionary_size(if version == ArchiveVersion::Rar70 {
                192 * 1024
            } else {
                128 * 1024
            }),
    )
    .entries([entry(b"first", &data), entry(b"second", &data)]);
    if let Some(filter) = filter {
        writer = writer.filter_policy(FilterPolicy::Explicit(crate::FilterSpec::whole(filter)));
    }
    let bytes = writer.finish().unwrap();
    let archive = Archive::parse_owned(bytes).unwrap();
    assert!(!archive.main.is_solid());
    assert!(archive.files().all(|file| !file.is_stored()
        && !file.is_split_before()
        && !file.is_split_after()
        && !file.decoded_compression_info().unwrap().solid));
    assert!(archive.files().all(|file| {
        file.decoded_compression_info().unwrap().algorithm_version
            == u8::from(version == ArchiveVersion::Rar70)
    }));
    assert!(archive.files().all(|file| file
        .hash
        .as_ref()
        .is_some_and(|hash| hash.hash_type == 0 && hash.data.len() == 32)));
    (archive, data)
}
fn extract(
    archive: &Archive,
    parallel: bool,
    options: crate::ArchiveReadOptions<'_>,
) -> (std::result::Result<(), String>, ExtractedFiles) {
    let mut writers = Vec::new();
    let mut open = |meta: &ExtractedEntryMeta| {
        let data = Rc::new(RefCell::new(Vec::new()));
        writers.push((meta.name.clone(), data.clone()));
        Ok(Box::new(Sink(data)) as Box<dyn Write>)
    };
    let result = if parallel {
        archive.extract_to_parallel_buffered(options, &mut open)
    } else {
        archive.extract_to(options, &mut open)
    };
    (
        result.map_err(|error| format!("{error:?}")),
        writers
            .into_iter()
            .map(|(name, data)| (name, data.borrow().clone()))
            .collect(),
    )
}
#[test]
fn independent_history_public_extraction_keeps_all_filter_bytes_and_bounded_routes() {
    for version in [ArchiveVersion::Rar50, ArchiveVersion::Rar70] {
        for filter in [
            None,
            Some(FilterKind::Delta { channels: 2 }),
            Some(FilterKind::E8),
            Some(FilterKind::E8E9),
            Some(FilterKind::Arm),
        ] {
            let (archive, data) = archive(version, filter);
            for limit in [None, Some(64 * 1024 * 1024)] {
                let mut options =
                    crate::ArchiveReadOptions::new().with_rar50_buffered_decode_limit(u64::MAX);
                options.max_reader_workspace_bytes = limit;
                let expected = extract(&archive, false, options);
                let actual = extract(&archive, true, options);
                assert_eq!(actual, expected);
                assert!(actual.0.is_ok());
                assert_eq!(
                    actual.1,
                    [
                        (b"first".to_vec(), data.clone()),
                        (b"second".to_vec(), data.clone())
                    ]
                );
            }
        }
    }
}
#[test]
fn independent_history_verification_keeps_only_the_ordered_verified_prefix() {
    for filter in [None, Some(FilterKind::Delta { channels: 2 })] {
        for hash_failure in [false, true] {
            let (mut archive, data) = archive(ArchiveVersion::Rar50, filter);
            for block in &mut archive.blocks {
                if let Block::File(file) = block {
                    if file.name == b"second" {
                        if hash_failure {
                            file.hash.as_mut().unwrap().data[0] ^= 1;
                        } else {
                            file.hash = None;
                            file.data_crc32 = Some(0);
                        }
                    }
                }
            }
            let options =
                crate::ArchiveReadOptions::new().with_rar50_buffered_decode_limit(u64::MAX);
            let expected = extract(&archive, false, options);
            let actual = extract(&archive, true, options);
            assert_eq!(actual.0, expected.0);
            assert!(actual.0.as_ref().unwrap_err().contains(if hash_failure {
                "HashMismatch"
            } else {
                "Crc32Mismatch"
            }));
            assert_eq!(actual.1, [(b"first".to_vec(), data.clone())]);
            // Existing sequential direct sinks open before verification;
            // independent publication opens only the verified prefix.
            assert_eq!(
                expected.1,
                [(b"first".to_vec(), data), (b"second".to_vec(), Vec::new())]
            );
        }
    }
}

#[cfg(feature = "encryption")]
#[test]
fn independent_history_encrypted_digest_and_password_errors_match_stateful_decode() {
    let data = b"encrypted independent Delta and BLAKE2sp MAC bytes\n".repeat(64);
    for filter in [None, Some(FilterKind::Delta { channels: 2 })] {
        let mut writer = Rar50Writer::new(
            WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only())
                .with_compression_level(1),
        )
        .entry(entry(b"encrypted", &data).with_password(b"password".to_vec()));
        if let Some(filter) = filter {
            writer = writer.filter_policy(FilterPolicy::Explicit(crate::FilterSpec::whole(filter)));
        }
        let bytes = writer.finish().unwrap();
        let archive = Archive::parse_owned(bytes).unwrap();
        assert!(archive
            .files()
            .all(|file| file.encrypted && !file.is_stored() && file.hash.is_some()));
        for password in [
            None,
            Some(b"wrong".as_slice()),
            Some(b"password".as_slice()),
        ] {
            let mut options =
                crate::ArchiveReadOptions::new().with_rar50_buffered_decode_limit(u64::MAX);
            options.password = password;
            let expected = extract(&archive, false, options);
            let actual = extract(&archive, true, options);
            assert_eq!(actual.0, expected.0);
            if password == Some(b"password".as_slice()) {
                assert!(actual.0.is_ok());
                assert_eq!(actual.1, expected.1);
                assert_eq!(actual.1, [(b"encrypted".to_vec(), data.clone())]);
            } else {
                assert!(actual.0.is_err());
                assert!(actual.1.is_empty());
            }
        }
    }
}

fn entry_result<B: Budget>(
    value: Result<ParallelExtractedEntry<B>>,
) -> std::result::Result<(String, Vec<u8>), String> {
    value
        .map(|entry| match entry {
            ParallelExtractedEntry::File { meta, data } => (format!("{meta:?}"), data.to_vec()),
            ParallelExtractedEntry::Opened(meta) => (format!("{meta:?}"), Vec::new()),
            ParallelExtractedEntry::Nothing => (String::new(), Vec::new()),
        })
        .map_err(|error| format!("{error:?}"))
}
#[test]
fn independent_history_worker_limited_keeps_original_attempts_callbacks_and_errors() {
    use crate::codec::workspace::RefusingBudget;
    for filter in [None, Some(FilterKind::Delta { channels: 2 })] {
        let (archive, _) = archive(ArchiveVersion::Rar50, filter);
        let file = archive.files().next().unwrap();
        let options = crate::ArchiveReadOptions::new().with_rar50_buffered_decode_limit(u64::MAX);
        let baseline = RefusingBudget::new(usize::MAX);
        drop(
            reference_decode_parallel_entry(&archive, file, None, u64::MAX, options, &baseline)
                .unwrap(),
        );
        assert_eq!(baseline.used(), 0);
        for fail_at in 0..=baseline.attempts() {
            for cancelled in [false, true] {
                let old = RefusingBudget::new(fail_at);
                let actual = RefusingBudget::new(fail_at);
                let old_token = crate::ReadCancellation::new();
                let actual_token = crate::ReadCancellation::new();
                // Use identical upfront cancellation, plus the decoder-level
                // checkpoint controls in codec/history_retention_tests.rs.
                if cancelled {
                    old_token.cancel();
                    actual_token.cancel();
                }
                let mut old_options = options;
                old_options.cancellation = Some(&old_token);
                let mut actual_options = options;
                actual_options.cancellation = Some(&actual_token);
                let expected = entry_result(reference_decode_parallel_entry(
                    &archive,
                    file,
                    None,
                    u64::MAX,
                    old_options,
                    &old,
                ));
                let output = entry_result(decode_parallel_entry(
                    &archive,
                    file,
                    &crate::rar50::Rar50KeyCache::default(),
                    u64::MAX,
                    actual_options,
                    false,
                    &actual,
                ));
                assert_eq!(output, expected, "filter={filter:?}, fail_at={fail_at}");
                assert_eq!(actual.attempts(), old.attempts());
                assert_eq!(actual.used(), 0);
                assert_eq!(old.used(), 0);
                assert_eq!(actual_token.is_cancelled(), old_token.is_cancelled());
            }
        }
    }
}

#[test]
fn independent_history_public_stream_and_scratch_fallbacks_keep_existing_results() {
    let dir = crate::scratch::case("independent-history-fallbacks");
    let scratch = crate::Rar50Scratch::new(&*dir, 64 * 1024);
    for filter in [None, Some(FilterKind::Delta { channels: 2 })] {
        let (archive, data) = archive(ArchiveVersion::Rar50, filter);
        for use_scratch in [false, true] {
            let mut options = crate::ArchiveReadOptions::new().with_rar50_buffered_decode_limit(1);
            if use_scratch {
                options.rar50_scratch = Some(&scratch);
            }
            let expected = extract(&archive, false, options);
            let actual = extract(&archive, true, options);
            assert_eq!(actual, expected);
            assert!(actual.0.is_ok());
            assert_eq!(
                actual.1,
                [
                    (b"first".to_vec(), data.clone()),
                    (b"second".to_vec(), data.clone())
                ]
            );
            assert_eq!(std::fs::read_dir(&*dir).unwrap().count(), 0);
        }
    }
}

#[test]
fn independent_history_late_publication_cancellation_keeps_the_verified_prefix() {
    let (archive, data) = archive(
        ArchiveVersion::Rar50,
        Some(FilterKind::Delta { channels: 2 }),
    );
    for parallel in [false, true] {
        let token = crate::ReadCancellation::new();
        let mut options =
            crate::ArchiveReadOptions::new().with_rar50_buffered_decode_limit(u64::MAX);
        options.cancellation = Some(&token);
        let mut writers = Vec::new();
        let mut open = |meta: &ExtractedEntryMeta| {
            let bytes = Rc::new(RefCell::new(Vec::new()));
            writers.push((meta.name.clone(), bytes.clone()));
            if meta.name == b"second" {
                token.cancel();
            }
            Ok(Box::new(Sink(bytes)) as Box<dyn Write>)
        };
        let error = if parallel {
            archive.extract_to_parallel_buffered(options, &mut open)
        } else {
            archive.extract_to(options, &mut open)
        }
        .unwrap_err();
        assert_eq!(error.kind(), crate::ErrorKind::Cancelled);
        let output: Vec<_> = writers
            .into_iter()
            .map(|(name, bytes)| {
                let data = bytes.borrow().clone();
                (name, data)
            })
            .collect();
        assert_eq!(
            output,
            [
                (b"first".to_vec(), data.clone()),
                (b"second".to_vec(), Vec::new())
            ]
        );
    }
}

// Original d2 private-worker pipeline, independent of the history selection.
fn reference_decode_parallel_entry<B: Budget>(
    archive: &Archive,
    file: &FileHeader,
    password: Option<&[u8]>,
    buffered_decode_limit: u64,
    options: crate::ArchiveReadOptions<'_>,
    allowance: &B,
) -> Result<ParallelExtractedEntry<B>> {
    options.check_cancelled()?;
    let mut budget = crate::output_limit::OutputBudget::new(options);
    file.check_dictionary_limit(options.rar50_dictionary_size_limit)?;
    file.check_output_limit(&budget)?;
    if file.redirection.is_some() {
        return Ok(ParallelExtractedEntry::Nothing);
    }
    // The only caller dispatches workers after excluding split members.
    let meta = file.metadata();
    if meta.is_directory {
        return Ok(ParallelExtractedEntry::Opened(meta));
    }
    let mut data = Buffer::new(allowance);
    let mut session = DecoderSession::with_allowance(password, buffered_decode_limit, allowance);
    session.decoder.read_control = budget.control.clone();
    session.scratch = options.rar50_scratch;
    budget.run(&file.name, &mut data, |writer| {
        session.write_file_to(archive, file, writer)
    })?;
    Ok(ParallelExtractedEntry::File { meta, data })
}

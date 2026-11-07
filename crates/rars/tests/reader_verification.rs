#![cfg(feature = "write")]

use rars::codec::rar50::{DecodedChunk, Unpack50Decoder};
use rars::rar50::{ArchiveEntry, Block, Rar50Writer, WriterOptions};
use rars::{
    test_volumes_with_options, test_volumes_with_options_and_callback, Archive, ArchiveReadOptions,
    ArchiveReader, ArchiveVersion, Builder, EntrySource, Error, ErrorKind, FeatureSet, FilterKind,
    FilterPolicy, FilterSpec, ReadCancellation,
};
use std::io::{self, Cursor, Read, Seek, SeekFrom};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};

#[path = "support/scratch.rs"]
mod scratch;

const DICTIONARY: u64 = 128 * 1024;

fn entry(name: &[u8], data: Vec<u8>) -> ArchiveEntry {
    ArchiveEntry::new(name.to_vec(), EntrySource::from_bytes(data))
}

fn options() -> WriterOptions {
    WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only())
        .with_compression_level(3)
        .with_dictionary_size(DICTIONARY)
}

fn encoded(data: Vec<u8>, policy: FilterPolicy) -> Vec<u8> {
    Rar50Writer::new(options())
        .entry(entry(b"payload", data))
        .filter_policy(policy)
        .finish()
        .unwrap()
}

fn late_filtered() -> (Vec<u8>, Vec<u8>) {
    let mut data = b"abc"
        .iter()
        .copied()
        .cycle()
        .take(300 * 1024)
        .collect::<Vec<_>>();
    data.extend_from_slice(&b"\xe8\0\0\0\0filtered bytes\n".repeat(2048));
    let policy = FilterPolicy::Explicit(FilterSpec::range(FilterKind::E8, 300 * 1024..data.len()));
    (encoded(data.clone(), policy), data)
}

fn cause(error: &Error) -> &Error {
    match error {
        Error::AtEntry { source, .. }
        | Error::AtArchiveOffset { source, .. }
        | Error::InVolume { source, .. } => cause(source),
        error => error,
    }
}

#[test]
fn verification_avoids_a_second_output_buffer_and_preserves_decode_routing() {
    let data = b"abc"
        .iter()
        .copied()
        .cycle()
        .take(4 * 1024 * 1024)
        .collect::<Vec<_>>();
    let archive = ArchiveReader::read_owned(encoded(data, FilterPolicy::None)).unwrap();
    let budget = ArchiveReadOptions::new().with_max_reader_workspace_bytes(1024 * 1024);
    assert_eq!(
        archive.test_with_options(budget).unwrap_err().kind(),
        ErrorKind::ResourceLimit
    );
    // Leave room for geometric output growth, but not a second 4 MiB
    // publication buffer retained beside the decoded bytes.
    let buffered_budget =
        ArchiveReadOptions::new().with_max_reader_workspace_bytes(7 * 1024 * 1024);
    archive.test_with_options(buffered_budget).unwrap();
    assert_eq!(
        archive
            .extract_to_parallel_buffered_with_options(buffered_budget, |_| Ok(
                Box::new(io::sink())
            ))
            .unwrap_err()
            .kind(),
        ErrorKind::ResourceLimit,
        "ordinary publication retains a second output buffer"
    );
    archive
        .test_with_options(budget.with_rar50_buffered_decode_limit(0))
        .unwrap();
    assert_eq!(
        archive
            .test_with_options(budget.with_rar50_buffered_decode_limit(u64::MAX))
            .unwrap_err()
            .kind(),
        ErrorKind::ResourceLimit
    );
    assert_eq!(
        archive
            .test_with_options(budget.with_rar50_dictionary_size_limit(DICTIONARY - 1))
            .unwrap_err()
            .kind(),
        ErrorKind::ResourceLimit
    );
    assert_eq!(
        archive
            .test_with_options(ArchiveReadOptions::new().with_max_reader_workspace_bytes(64 * 1024))
            .unwrap_err()
            .kind(),
        ErrorKind::ResourceLimit
    );
}

#[test]
fn filtered_verification_charges_total_output_once_and_preserves_explicit_routing() {
    let (bytes, data) = late_filtered();
    let archive = ArchiveReader::read_owned(bytes.clone()).unwrap();
    let Archive::Rar50Plus(typed) = &archive else {
        unreachable!()
    };
    let file = typed.files().next().unwrap();
    let info = file.decoded_compression_info().unwrap();
    let mut emitted = 0;
    let result = Unpack50Decoder::new().decode_member_from_reader_with_dictionary_to_sink(
        &mut &bytes[file.block.data_range.clone()],
        info.algorithm_version,
        data.len(),
        info.dictionary_size as usize,
        false,
        |chunk| {
            emitted += match chunk {
                DecodedChunk::Bytes(bytes) => bytes.len(),
                DecodedChunk::Repeated { len, .. } => len,
            };
            Ok::<(), io::Error>(())
        },
    );
    result.unwrap();
    assert_eq!(emitted, data.len());
    let exact = ArchiveReadOptions::new()
        .with_max_member_output_bytes(data.len() as u64)
        .with_max_total_output_bytes(data.len() as u64);
    let mut seen = Vec::new();
    archive
        .test_with_options_and_callback(exact, |meta| {
            seen.push(meta.name.clone());
            Ok(())
        })
        .unwrap();
    assert_eq!(seen, [b"payload".to_vec()]);
    assert_eq!(archive.read_member_at(0, None).unwrap().unwrap(), data);
    assert!(matches!(
        cause(
            &archive
                .test_with_options(exact.with_max_total_output_bytes(data.len() as u64 - 1))
                .unwrap_err()
        ),
        Error::TotalOutputLimitExceeded { .. }
    ));
    archive
        .test_with_options(exact.with_rar50_buffered_decode_limit(0))
        .unwrap();
    archive
        .test_with_options(exact.with_rar50_buffered_decode_limit(data.len() as u64))
        .unwrap();
}

struct ProbeReader {
    data: Cursor<Vec<u8>>,
    start: u64,
    armed: Arc<AtomicBool>,
    attempts: Arc<AtomicUsize>,
    fail: bool,
    cancel_on_read: Option<ReadCancellation>,
}
impl Read for ProbeReader {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if self.armed.load(Ordering::Relaxed)
            && self.data.position() == self.start
            && !bytes.is_empty()
        {
            let attempt = self.attempts.fetch_add(1, Ordering::Relaxed);
            if self.fail {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "source refused",
                ));
            }
            if attempt == 0 {
                if let Some(token) = &self.cancel_on_read {
                    token.cancel();
                }
            }
        }
        self.data.read(bytes)
    }
}
impl Seek for ProbeReader {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        self.data.seek(from)
    }
}
fn reader(
    bytes: Vec<u8>,
    fail: bool,
    cancel_on_read: Option<ReadCancellation>,
) -> (Archive, Arc<AtomicUsize>) {
    let archive = ArchiveReader::read(&bytes).unwrap();
    let Archive::Rar50Plus(typed) = archive else {
        unreachable!()
    };
    let start = typed.files().next().unwrap().block.data_range.start as u64;
    let armed = Arc::new(AtomicBool::new(false));
    let attempts = Arc::new(AtomicUsize::new(0));
    let source = ProbeReader {
        data: Cursor::new(bytes),
        start,
        armed: armed.clone(),
        attempts: attempts.clone(),
        fail,
        cancel_on_read,
    };
    let archive = ArchiveReader::read_reader(source).unwrap();
    armed.store(true, Ordering::Relaxed);
    (archive, attempts)
}

#[test]
fn admission_precedes_probe_and_source_errors_are_never_retried() {
    let bytes = encoded(b"abc".repeat(128 * 1024), FilterPolicy::None);
    let (archive, attempts) = reader(bytes.clone(), true, None);
    let error = archive
        .test_with_options(ArchiveReadOptions::new().with_max_member_output_bytes(1))
        .unwrap_err();
    assert!(matches!(
        cause(&error),
        Error::MemberOutputLimitExceeded { .. }
    ));
    assert_eq!(attempts.load(Ordering::Relaxed), 0);
    assert_eq!(archive.test(None).unwrap_err().kind(), ErrorKind::Io);
    assert_eq!(attempts.load(Ordering::Relaxed), 1);
    let mut archive = ArchiveReader::read_owned(bytes).unwrap();
    let Archive::Rar50Plus(typed) = &mut archive else {
        unreachable!()
    };
    for block in &mut typed.blocks {
        if let Block::File(file) = block {
            file.hash = None;
            file.data_crc32 = Some(0);
        }
    }
    let mut seen = 0;
    let error = archive
        .test_with_options_and_callback(ArchiveReadOptions::new(), |_| {
            seen += 1;
            Ok(())
        })
        .unwrap_err();
    assert!(matches!(cause(&error), Error::Crc32Mismatch { .. }));
    assert_eq!(
        seen, 0,
        "failed parallel verification publishes no metadata"
    );
}

#[test]
fn cancellation_during_payload_read_is_not_hidden_or_reported_as_success() {
    let (bytes, _) = late_filtered();
    let token = ReadCancellation::new();
    let (archive, attempts) = reader(bytes, false, Some(token.clone()));
    let mut seen = 0;
    let error = archive
        .test_with_options_and_callback(ArchiveReadOptions::new().with_cancellation(&token), |_| {
            seen += 1;
            Ok(())
        })
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Cancelled);
    assert_eq!(
        attempts.load(Ordering::Relaxed),
        1,
        "default buffered verification reads the packed stream once"
    );
    assert_eq!(seen, 0);
}

#[test]
fn filtered_member_above_the_default_buffer_limit_streams_once() {
    let (bytes, _) = late_filtered();
    let (mut archive, attempts) = reader(bytes, false, None);
    let required = 16 * 1024 * 1024 + 1;
    let Archive::Rar50Plus(typed) = &mut archive else {
        unreachable!()
    };
    for block in &mut typed.blocks {
        if let Block::File(file) = block {
            file.unpacked_size = required;
        }
    }
    let error = archive.test(None).unwrap_err();
    // The size claims more output than the packed stream holds, so streaming
    // it runs out of input, and the reader does not go back for a second pass.
    assert!(matches!(
        cause(&error),
        Error::Codec(rars::codec::Error::NeedMoreInput)
    ));
    assert_eq!(attempts.load(Ordering::Relaxed), 1);
}

#[cfg(feature = "encryption")]
#[test]
fn filtered_encrypted_verification_detects_corruption() {
    let (_, data) = late_filtered();
    let policy = FilterPolicy::Explicit(FilterSpec::range(FilterKind::E8, 300 * 1024..data.len()));
    let bytes = Rar50Writer::new(options())
        .entry(entry(b"payload", data.clone()).with_password(b"secret"))
        .filter_policy(policy)
        .finish()
        .unwrap();
    let mut archive = ArchiveReader::read_owned(bytes).unwrap();
    let exact =
        ArchiveReadOptions::with_password(b"secret").with_max_total_output_bytes(data.len() as u64);
    archive.test_with_options(exact).unwrap();
    assert_eq!(
        archive.read_member_at(0, Some(b"secret")).unwrap().unwrap(),
        data
    );
    let Archive::Rar50Plus(typed) = &mut archive else {
        unreachable!()
    };
    for block in &mut typed.blocks {
        if let Block::File(file) = block {
            file.hash = None;
            file.data_crc32 = Some(0);
        }
    }
    assert!(matches!(
        cause(&archive.test_with_options(exact).unwrap_err()),
        Error::Crc32Mismatch { .. }
    ));
}

#[test]
fn callbacks_are_ordered_and_callback_cancellation_and_errors_abort() {
    let mut builder = Builder::new(ArchiveVersion::Rar50).store(false);
    builder
        .add_bytes(b"first".to_vec(), b"first".repeat(1000), None, None)
        .unwrap();
    builder.add_directory(b"dir".to_vec(), None, None).unwrap();
    builder
        .add_bytes(b"last".to_vec(), vec![], None, None)
        .unwrap();
    let archive = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
    let mut seen = Vec::new();
    archive
        .test_with_options_and_callback(ArchiveReadOptions::new(), |meta| {
            seen.push((meta.name.clone(), meta.is_directory));
            Ok(())
        })
        .unwrap();
    assert_eq!(
        seen,
        [
            (b"first".to_vec(), false),
            (b"dir".to_vec(), true),
            (b"last".to_vec(), false)
        ]
    );
    let token = ReadCancellation::new();
    let mut seen = 0;
    assert_eq!(
        archive
            .test_with_options_and_callback(
                ArchiveReadOptions::new().with_cancellation(&token),
                |_| {
                    seen += 1;
                    token.cancel();
                    Ok(())
                }
            )
            .unwrap_err()
            .kind(),
        ErrorKind::Cancelled
    );
    assert_eq!(seen, 1);
    assert_eq!(
        archive
            .test_with_options_and_callback(ArchiveReadOptions::new(), |_| Err(
                Error::InvalidArgument("callback refused")
            ))
            .unwrap_err(),
        Error::InvalidArgument("callback refused")
    );
}

#[test]
fn legacy_callbacks_and_volume_api_preserve_order_and_output_limits() {
    for version in [
        ArchiveVersion::Rar14,
        ArchiveVersion::Rar29,
        ArchiveVersion::Rar40,
    ] {
        let mut builder = Builder::new(version).store(true);
        builder
            .add_bytes(b"first".to_vec(), b"first".to_vec(), None, None)
            .unwrap();
        builder.add_directory(b"dir".to_vec(), None, None).unwrap();
        builder
            .add_bytes(b"last".to_vec(), b"last".to_vec(), None, None)
            .unwrap();
        let archive = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
        let exact = ArchiveReadOptions::new().with_max_total_output_bytes(9);
        let mut seen = Vec::new();
        archive
            .test_with_options_and_callback(exact, |meta| {
                seen.push(meta.name.clone());
                Ok(())
            })
            .unwrap();
        assert_eq!(seen, [b"first".to_vec(), b"dir".to_vec(), b"last".to_vec()]);
        let mut volume_seen = Vec::new();
        test_volumes_with_options_and_callback(std::slice::from_ref(&archive), exact, |meta| {
            volume_seen.push(meta.name.clone());
            Ok(())
        })
        .unwrap();
        assert_eq!(volume_seen, seen);
        let mut seen = Vec::new();
        let error = archive
            .test_with_options_and_callback(exact.with_max_total_output_bytes(8), |meta| {
                seen.push(meta.name.clone());
                Ok(())
            })
            .unwrap_err();
        assert!(matches!(
            cause(&error),
            Error::TotalOutputLimitExceeded { .. }
        ));
        assert_eq!(seen, [b"first".to_vec(), b"dir".to_vec()]);
    }
}

#[test]
fn solid_and_encrypted_verification_preserves_history_and_exact_output_budgets() {
    for encrypted in [false, true] {
        if encrypted && !cfg!(feature = "encryption") {
            continue;
        }
        let mut builder = Builder::new(ArchiveVersion::Rar50).store(false).solid(true);
        if encrypted {
            builder = builder.password(Some(b"secret".to_vec()));
        }
        let data = b"shared solid dictionary bytes".repeat(8192);
        for name in [b"first".to_vec(), b"second".to_vec()] {
            builder.add_bytes(name, data.clone(), None, None).unwrap();
        }
        let archive = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
        let mut options =
            ArchiveReadOptions::new().with_max_total_output_bytes((data.len() * 2) as u64);
        options.password = encrypted.then_some(b"secret".as_slice());
        let mut seen = Vec::new();
        archive
            .test_with_options_and_callback(options, |meta| {
                seen.push(meta.name.clone());
                Ok(())
            })
            .unwrap();
        assert_eq!(seen, [b"first".to_vec(), b"second".to_vec()]);
        archive
            .test_with_options(options.with_rar50_buffered_decode_limit(0))
            .unwrap();
        if encrypted {
            assert!(archive
                .test_with_options(ArchiveReadOptions::with_password(b"wrong"))
                .is_err());
        }
    }
}

#[test]
fn split_filtered_encrypted_and_solid_members_use_verification_without_duplicate_callbacks() {
    for (prefix, count, padded, password) in [
        ("multivol", 3, false, None),
        ("encrypted_multivol", 3, false, Some(b"password".as_slice())),
        ("solid_multivol", 6, true, None),
    ] {
        if password.is_some() && !cfg!(feature = "encryption") {
            continue;
        }
        let volumes: Vec<_> = (1..=count)
            .map(|index| {
                let number = if padded {
                    format!("{index:02}")
                } else {
                    index.to_string()
                };
                ArchiveReader::read_path_with_options(
                    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                        .join("tests/fixtures/rar50")
                        .join(format!("{prefix}.part{number}.rar")),
                    ArchiveReadOptions::with_optional_password(password),
                )
                .unwrap()
            })
            .collect();
        let mut expected = Vec::new();
        rars::extract_volumes_to_with_options(
            &volumes,
            ArchiveReadOptions::with_optional_password(password)
                .with_rar50_buffered_decode_limit(u64::MAX),
            |meta| {
                expected.push(meta.name.clone());
                Ok(Box::new(io::sink()))
            },
        )
        .unwrap();
        let mut seen = Vec::new();
        test_volumes_with_options_and_callback(
            &volumes,
            ArchiveReadOptions::with_optional_password(password),
            |meta| {
                seen.push(meta.name.clone());
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(seen, expected, "{prefix}");
    }
    let (bytes, data) = late_filtered();
    let parsed = ArchiveReader::read_owned(bytes).unwrap();
    // A real filtered archive also exercises the volume API with one physical
    // volume; fragmented filters are covered below.
    test_volumes_with_options(
        &[parsed],
        ArchiveReadOptions::new().with_max_total_output_bytes(data.len() as u64),
    )
    .unwrap();
}

#[test]
fn fragmented_filtered_verification_charges_once_and_preserves_scratch_limits() {
    let (_, data) = late_filtered();
    let policy = FilterPolicy::Explicit(FilterSpec::range(FilterKind::E8, 300 * 1024..data.len()));
    let mut sink = rars::rar50::CollectedVolumes::new();
    let root = scratch::case("verification-filtered-splits");
    rars::rar50::write_streaming_volumes_to(
        &[entry(b"payload", data.clone())],
        options(),
        rars::rar50::ArchiveExtras::default().with_filter_policy(policy),
        256,
        &mut sink,
        &rars::WriterResources::new(64 * 1024 * 1024).with_temp_dir(root.to_path_buf()),
    )
    .unwrap();
    let volumes = sink
        .take()
        .into_iter()
        .map(|bytes| ArchiveReader::read_owned(bytes).unwrap())
        .collect::<Vec<_>>();
    assert!(volumes.len() > 1);
    let exact = ArchiveReadOptions::new().with_max_total_output_bytes(data.len() as u64);
    let mut seen = Vec::new();
    test_volumes_with_options_and_callback(&volumes, exact, |meta| {
        seen.push(meta.name.clone());
        Ok(())
    })
    .unwrap();
    assert_eq!(seen, [b"payload".to_vec()]);
    test_volumes_with_options(&volumes, exact.with_rar50_buffered_decode_limit(0)).unwrap();
    let scratch =
        rars::Rar50Scratch::new(&*root, 2 * 1024 * 1024).with_filter_memory_limit(128 * 1024);
    test_volumes_with_options(
        &volumes,
        exact
            .with_rar50_buffered_decode_limit(0)
            .with_rar50_scratch(&scratch),
    )
    .unwrap();
    let small = rars::Rar50Scratch::new(&*root, 1).with_filter_memory_limit(128 * 1024);
    assert_eq!(
        test_volumes_with_options(
            &volumes,
            exact
                .with_rar50_buffered_decode_limit(0)
                .with_rar50_scratch(&small)
        )
        .unwrap_err()
        .kind(),
        ErrorKind::ResourceLimit
    );
}

#[test]
fn split_callbacks_preserve_cancellation_errors_and_incomplete_volume_detection() {
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/rar50");
    let volumes = (1..=3)
        .map(|index| {
            ArchiveReader::read_path(fixture.join(format!("multivol.part{index}.rar"))).unwrap()
        })
        .collect::<Vec<_>>();
    let token = ReadCancellation::new();
    let mut seen = 0;
    let error = test_volumes_with_options_and_callback(
        &volumes,
        ArchiveReadOptions::new().with_cancellation(&token),
        |_| {
            seen += 1;
            token.cancel();
            Ok(())
        },
    )
    .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Cancelled);
    assert_eq!(seen, 1);
    assert_eq!(
        test_volumes_with_options_and_callback(&volumes, ArchiveReadOptions::new(), |_| Err(
            Error::InvalidArgument("callback refused")
        ))
        .unwrap_err(),
        Error::InvalidArgument("callback refused")
    );
    let error = test_volumes_with_options(&volumes[..2], ArchiveReadOptions::new()).unwrap_err();
    assert!(matches!(
        cause(&error),
        Error::InvalidHeader("RAR 5 split entry is incomplete")
    ));
    let error = test_volumes_with_options(&volumes[1..], ArchiveReadOptions::new()).unwrap_err();
    assert!(matches!(
        cause(&error),
        Error::InvalidHeader("RAR 5 split entry is missing its first part")
    ));
}

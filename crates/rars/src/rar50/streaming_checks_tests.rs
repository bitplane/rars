use super::*;
use crate::rar50::{
    ArchiveEntry, Block, FileHash, FilterPolicy, Rar50Writer, WriterOptions, HFL_SPLIT_AFTER,
    HFL_SPLIT_BEFORE,
};
use crate::{ArchiveVersion, EntrySource, FeatureSet};
use std::cell::Cell;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Work {
    bytes: usize,
    zeroes: usize,
    repeated_bytes: usize,
    repeated_zeroes: usize,
}

std::thread_local! {
    static WORK: Cell<Work> = const { Cell::new(Work {
        bytes: 0, zeroes: 0, repeated_bytes: 0, repeated_zeroes: 0,
    }) };
}

pub(super) fn record_crc_work(len: usize, zeroes: bool) {
    WORK.with(|work| {
        let mut value = work.get();
        if zeroes {
            value.zeroes += len;
        } else {
            value.bytes += len;
        }
        work.set(value);
    });
}

pub(super) fn record_repeated_output(len: usize, zeroes: bool) {
    WORK.with(|work| {
        let mut value = work.get();
        value.repeated_bytes += len;
        if zeroes {
            value.repeated_zeroes += len;
        }
        work.set(value);
    });
}

fn measured<T>(run: impl FnOnce() -> T) -> (T, Work) {
    WORK.with(|work| work.set(Work::default()));
    let value = run();
    (value, WORK.with(Cell::get))
}

fn fixture(data: &[u8], stored: bool, encrypted: bool) -> (Archive, FileHeader) {
    let mut input = ArchiveEntry::new(b"payload".to_vec(), EntrySource::from_bytes(data.to_vec()));
    if encrypted {
        input = input.with_password(b"password".to_vec());
    }
    let bytes = Rar50Writer::new(
        WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only())
            .with_compression_level(if stored { 0 } else { 1 })
            .with_dictionary_size(128 * 1024),
    )
    .entry(input)
    .filter_policy(FilterPolicy::None)
    .finish()
    .unwrap();
    let archive = Archive::parse_with_password(&bytes, Some(b"password")).unwrap();
    let file = archive.files().next().unwrap().clone();
    assert_eq!(file.is_stored(), stored);
    (archive, file)
}

fn ordinary(archive: &Archive, file: &FileHeader) -> (Result<Vec<u8>>, Work) {
    measured(|| {
        let mut session =
            DecoderSession::with_allowance(Some(b"password"), 0, &Allowance::default());
        let mut output = Vec::new();
        session.write_file_to(archive, file, &mut output)?;
        Ok(output)
    })
}

#[test]
fn ordinary_streaming_skips_crc_work_only_when_integrity_does_not_use_it() {
    let data = b"ordinary streaming integrity bytes\n".repeat(4096);
    for stored in [false, true] {
        let (archive, original) = fixture(&data, stored, false);
        for layout in ["hash", "none", "crc", "unknown"] {
            let mut file = original.clone();
            match layout {
                "hash" => file.data_crc32 = Some(crc32(&data) ^ 1),
                "none" => {
                    file.data_crc32 = None;
                    file.hash = None;
                }
                "crc" => file.hash = None,
                "unknown" => {
                    file.hash = Some(FileHash {
                        hash_type: 7,
                        data: vec![1],
                    });
                }
                _ => unreachable!(),
            }
            let (result, work) = ordinary(&archive, &file);
            assert_eq!(result.unwrap(), data);
            assert_eq!(
                work.bytes + work.zeroes,
                if matches!(layout, "crc" | "unknown") {
                    data.len()
                } else {
                    0
                },
                "stored={stored}, layout={layout}, work={work:?}",
            );
        }
    }
}

#[test]
fn optional_repeated_output_keeps_hash_and_real_zero_run_delivery() {
    let data = vec![0; 200 * 1024];
    let (archive, mut file) = fixture(&data, false, false);
    file.data_crc32 = Some(1);
    let (result, work) = ordinary(&archive, &file);
    assert_eq!(result.unwrap(), data);
    assert!(
        work.repeated_zeroes > 64 * 1024,
        "must use actual codec zero runs"
    );
    assert_eq!(work.bytes + work.zeroes, 0, "{work:?}");
}

#[test]
fn optional_repeated_output_preserves_nonzero_hash_and_sink_failure_order() {
    let data = vec![0xff; 140_000];
    let mut output = Vec::new();
    let expected = blake2sp::hash(&data);
    let mut hash = Some((expected, blake2sp::Hasher::new()));
    let (result, work) = measured(|| {
        write_repeated_chunk_with_optional_crc(&mut output, None, &mut hash, 0xff, data.len())
    });
    result.unwrap();
    assert_eq!(output, data);
    assert_eq!(hash.unwrap().1.finalize(), expected);
    assert_eq!(work.bytes + work.zeroes, 0);
    assert_eq!(work.repeated_bytes, data.len());

    let mut crc = Crc32::new();
    let mut hash = Some((expected, blake2sp::Hasher::new()));
    let (result, work) =
        measured(|| write_repeated_chunk(&mut RejectWrite, &mut crc, &mut hash, 0, 100_000));
    assert!(result.is_err());
    assert_eq!(crc.finish(), Crc32::new().finish());
    assert_eq!(hash.unwrap().1.finalize(), blake2sp::hash(b""));
    assert_eq!(work, Work::default());
}

#[test]
fn ordinary_streaming_keeps_checksum_authority_and_malformed_hash_precedence() {
    let data = b"checksum authority\n".repeat(8192);
    for stored in [false, true] {
        let (archive, original) = fixture(&data, stored, false);
        for layout in ["bad hash", "bad crc", "unknown hash", "malformed hash"] {
            let mut file = original.clone();
            match layout {
                "bad hash" => file.hash.as_mut().unwrap().data[0] ^= 1,
                "bad crc" => {
                    file.hash = None;
                    file.data_crc32 = Some(crc32(&data) ^ 1);
                }
                "unknown hash" => {
                    file.hash = Some(FileHash {
                        hash_type: 99,
                        data: vec![1],
                    });
                    file.data_crc32 = Some(crc32(&data) ^ 1);
                }
                "malformed hash" => {
                    file.hash.as_mut().unwrap().data.pop();
                    file.data_crc32 = Some(crc32(&data) ^ 1);
                }
                _ => unreachable!(),
            }
            let (result, work) = ordinary(&archive, &file);
            let error = result.unwrap_err();
            match layout {
                "bad hash" => {
                    assert!(matches!(
                        error.root_cause(),
                        Error::HashMismatch { hash_type: 0 }
                    ));
                    assert_eq!(work.bytes + work.zeroes, 0);
                }
                "bad crc" | "unknown hash" => {
                    assert!(matches!(error.root_cause(), Error::Crc32Mismatch { .. }));
                    assert_eq!(work.bytes + work.zeroes, data.len());
                }
                "malformed hash" => {
                    assert!(matches!(
                        error.root_cause(),
                        Error::InvalidHeader("RAR 5 BLAKE2sp hash record has invalid length")
                    ));
                    assert_eq!(work, Work::default());
                }
                _ => unreachable!(),
            }
        }
    }
}

struct RejectWrite;
impl Write for RejectWrite {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("ordinary streaming sink failed"))
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn ordinary_streaming_preserves_sink_error_context_before_hash_failure() {
    let data = b"sink failure must precede final checksum\n".repeat(4096);
    for stored in [false, true] {
        let (archive, mut file) = fixture(&data, stored, false);
        file.hash.as_mut().unwrap().data[0] ^= 1;
        let mut session = DecoderSession::with_allowance(None, 0, &Allowance::default());
        let (result, work) = measured(|| session.write_file_to(&archive, &file, &mut RejectWrite));
        let error = result.unwrap_err();
        assert_eq!(error.kind(), crate::ErrorKind::Io);
        assert_eq!(
            error.entry_context().unwrap().1,
            if stored { "writing" } else { "decoding" },
        );
        assert_eq!(work.bytes + work.zeroes, 0);
    }
}

#[test]
#[cfg(feature = "encryption")]
fn ordinary_encrypted_streaming_preserves_crc_mac_hash_mac_padding_and_truncation() {
    let data = b"encrypted MAC payload!".repeat(4097);
    for stored in [false, true] {
        let (archive, original) = fixture(&data, stored, true);
        assert!(original.uses_hash_mac());
        let (result, work) = ordinary(&archive, &original);
        assert_eq!(result.unwrap(), data);
        assert_eq!(work.bytes + work.zeroes, 0);
        let mut crc_only = original.clone();
        crc_only.hash = None;
        let (result, work) = ordinary(&archive, &crc_only);
        assert_eq!(result.unwrap(), data);
        assert_eq!(work.bytes + work.zeroes, data.len());
        crc_only.data_crc32 = Some(crc_only.data_crc32.unwrap() ^ 1);
        assert!(matches!(
            ordinary(&archive, &crc_only).0.unwrap_err().root_cause(),
            Error::Crc32Mismatch { .. },
        ));
        let mut bad_hash = original.clone();
        bad_hash.hash.as_mut().unwrap().data[0] ^= 1;
        assert!(matches!(
            ordinary(&archive, &bad_hash).0.unwrap_err().root_cause(),
            Error::HashMismatch { hash_type: 0 },
        ));
        let mut truncated = original.clone();
        truncated.block.data_range.end -= 1;
        truncated.block.data_size = Some(truncated.block.data_range.len() as u64);
        let error = ordinary(&archive, &truncated).0.unwrap_err();
        // Compare the complete legacy path, including reader admission.
        // Shortening the declared cipher payload fails its alignment check
        // before either stored or compressed decoding can read it.
        let mut decoder = ReaderState::new(&Allowance::default());
        let expected = (|| {
            let (mut packed, keys) = truncated.packed_reader_with_allowance(
                &archive,
                Some(b"password"),
                &Allowance::default(),
            )?;
            truncated.stream_packed_with_decoder(
                &mut packed,
                keys.as_ref(),
                &mut decoder,
                0,
                None,
                &mut std::io::sink(),
            )
        })()
        .unwrap_err();
        assert_eq!(error.root_cause(), expected.root_cause());
        assert!(matches!(
            expected.root_cause(),
            Error::InvalidHeader("RAR 5 encrypted file payload is not block aligned")
        ));
        if stored {
            // A data byte past the unpacked size counts as padding, which
            // holds anything; the hash over the shorter data refuses it.
            let mut short = original.clone();
            short.unpacked_size -= 1;
            let error = ordinary(&archive, &short).0.unwrap_err();
            assert!(matches!(
                error.root_cause(),
                Error::HashMismatch { hash_type: 0 }
            ));
        }
    }
}

#[test]
fn ordinary_streaming_admission_and_source_open_precede_malformed_hash() {
    let dir = crate::scratch::case("ordinary-streaming-precedence");
    let path = dir.join("removed.rar");
    for stored in [false, true] {
        let data = b"header resource admission".repeat(4096);
        let (original, _) = fixture(&data, stored, false);
        let crate::source::ArchiveSource::Memory(bytes) = &original.source else {
            unreachable!()
        };
        std::fs::write(&path, bytes).unwrap();
        let mut archive = Archive::parse_path(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        let Block::File(file) = archive
            .blocks
            .iter_mut()
            .find(|b| matches!(b, Block::File(_)))
            .unwrap()
        else {
            unreachable!()
        };
        file.hash.as_mut().unwrap().data.pop();
        let mut opened = 0;
        let limit = data.len() as u64 - 1;
        for options in [
            crate::ArchiveReadOptions::new().with_max_member_output_bytes(limit),
            crate::ArchiveReadOptions::new().with_max_total_output_bytes(limit),
        ] {
            let error = archive
                .extract_to(options.with_rar50_buffered_decode_limit(0), |_| {
                    opened += 1;
                    Ok(Box::new(std::io::sink()) as Box<dyn Write>)
                })
                .unwrap_err();
            assert_eq!(error.kind(), crate::ErrorKind::ResourceLimit);
        }
        assert_eq!(opened, 0);
        let file = archive.files().next().unwrap();
        if !stored {
            let error = archive
                .extract_to(
                    crate::ArchiveReadOptions::new()
                        .with_rar50_buffered_decode_limit(0)
                        .with_rar50_dictionary_size_limit(0),
                    |_| {
                        opened += 1;
                        Ok(Box::new(std::io::sink()) as Box<dyn Write>)
                    },
                )
                .unwrap_err();
            assert_eq!(error.kind(), crate::ErrorKind::ResourceLimit);
            assert_eq!(opened, 0);
        }
        let (result, work) = ordinary(&archive, file);
        let error = result.unwrap_err();
        assert_eq!(error.kind(), crate::ErrorKind::Io);
        assert_eq!(work, Work::default());
    }
}

#[test]
fn split_compressed_members_retain_always_crc_work() {
    let data = b"split compressed hash and crc\n".repeat(8192);
    let (archive, original) = fixture(&data, false, false);
    let middle = original.block.data_range.start + original.packed_size() as usize / 2;
    let mut first = original.clone();
    first.block.flags |= HFL_SPLIT_AFTER;
    first.block.data_range.end = middle;
    first.block.data_size = Some(first.block.data_range.len() as u64);
    let mut last = original;
    last.block.flags |= HFL_SPLIT_BEFORE;
    last.block.data_range.start = middle;
    last.block.data_size = Some(last.block.data_range.len() as u64);
    last.data_crc32 = Some(1); // Its valid BLAKE remains authoritative.
    let mut volume1 = archive.clone();
    volume1.blocks = vec![Block::File(first.clone())];
    let mut volume2 = archive;
    volume2.blocks = vec![Block::File(last.clone())];
    let volumes = [volume1, volume2];
    let mut split = PendingSplitRefs::with_allowance(&first, 0, 0, &Allowance::default()).unwrap();
    split.append(1, 0).unwrap();
    let mut session = DecoderSession::with_allowance(None, 0, &Allowance::default());
    let mut output = Vec::new();
    let (result, work) =
        measured(|| session.stream_split_to(&volumes, &split, &last, None, &mut output));
    result.unwrap();
    assert_eq!(output, data);
    assert_eq!(work.bytes + work.zeroes, data.len());
}

#[test]
fn optional_crc_policy_keeps_scratch_dispatch_before_hash_initialization() {
    let dir = crate::scratch::case("ordinary-streaming-scratch-policy");
    let policy = crate::Rar50Scratch::new(&*dir, 1024 * 1024);
    let data = b"scratch route bytes\n".repeat(4096);
    let (archive, mut file) = fixture(&data, false, false);
    let mut session = DecoderSession::with_allowance(None, 0, &Allowance::default());
    session.scratch = Some(&policy);
    let mut output = Vec::new();
    session.write_file_to(&archive, &file, &mut output).unwrap();
    assert_eq!(output, data);
    assert_eq!(std::fs::read_dir(&*dir).unwrap().count(), 0);
    file.hash.as_mut().unwrap().data.pop();
    file.block.data_range.end = file.block.data_range.start;
    file.block.data_size = Some(0);
    let error = session
        .write_file_to(&archive, &file, &mut std::io::sink())
        .unwrap_err();
    assert!(matches!(
        error.root_cause(),
        Error::Codec(crate::codec::Error::NeedMoreInput)
    ));
    assert_eq!(std::fs::read_dir(&*dir).unwrap().count(), 0);
}

#[test]
fn optional_crc_keeps_limited_growth_and_refusals_identical_to_legacy_streaming() {
    use crate::codec::workspace::RefusingBudget;
    let data = b"limited CRC policy bytes\n".repeat(4096);
    let (archive, file) = fixture(&data, false, false);
    let run = |budget: &RefusingBudget, optional| {
        let mut session = DecoderSession::with_allowance(None, 0, budget);
        let mut output = Buffer::new(budget);
        if optional {
            session.write_file_to(&archive, &file, &mut output)?;
        } else {
            let mut decoder = session.decoder.try_clone()?;
            let (mut packed, keys) = file.packed_reader_with_allowance(&archive, None, budget)?;
            file.stream_packed_with_decoder(
                &mut packed,
                keys.as_ref(),
                &mut decoder,
                0,
                None,
                &mut output,
            )?;
        }
        assert_eq!(&output[..], &data);
        Ok::<(), Error>(())
    };
    let baseline = RefusingBudget::new(usize::MAX);
    run(&baseline, false).unwrap();
    let attempts = baseline.attempts();
    assert!(attempts > 0);
    assert_eq!(baseline.used(), 0);
    for fail_at in 0..=attempts {
        let old = RefusingBudget::new(fail_at);
        let new = RefusingBudget::new(fail_at);
        let expected = run(&old, false);
        let actual = run(&new, true);
        assert_eq!(
            actual.as_ref().err().map(Error::kind),
            expected.as_ref().err().map(Error::kind),
            "allocation {fail_at}"
        );
        assert_eq!(new.attempts(), old.attempts(), "allocation {fail_at}");
        assert_eq!(new.used(), 0);
        assert_eq!(old.used(), 0);
    }
}

#[test]
fn optional_crc_preserves_bad_hash_checkpoint_for_a_history_dependent_successor() {
    let mut random = 0x1234_5678u32;
    let seed: Vec<_> = (0..32749)
        .map(|_| {
            random ^= random << 13;
            random ^= random >> 17;
            random ^= random << 5;
            random as u8
        })
        .collect();
    let first = seed.repeat(4);
    let next = first[127..4224].to_vec();
    let mut builder = crate::Builder::new(ArchiveVersion::Rar50)
        .store(false)
        .solid(true)
        .compression_level(Some(1));
    builder
        .add_bytes(b"first".to_vec(), first, None, None)
        .unwrap();
    builder
        .add_bytes(b"next".to_vec(), next.clone(), None, None)
        .unwrap();
    let archive = Archive::parse_owned(builder.to_bytes().unwrap()).unwrap();
    let files: Vec<_> = archive.files().collect();
    assert!(files[1].decoded_compression_info().unwrap().solid);
    assert!(
        files[1].packed_size() < 128,
        "successor must use predecessor history"
    );

    let different = b"failed member replaces the old raw dictionary\n".repeat(4096);
    let (failed_archive, valid) = fixture(&different, false, false);
    let mut corrupt = valid.clone();
    corrupt.hash.as_mut().unwrap().data[0] ^= 1;
    let mut session = DecoderSession::with_allowance(None, 0, &Allowance::default());
    session
        .write_file_to(&archive, files[0], &mut std::io::sink())
        .unwrap();
    let (result, work) =
        measured(|| session.write_file_to(&failed_archive, &corrupt, &mut std::io::sink()));
    assert!(matches!(
        result.unwrap_err().root_cause(),
        Error::HashMismatch { hash_type: 0 }
    ));
    assert_eq!(
        work.bytes + work.zeroes,
        0,
        "bad digest does not change hash authority"
    );
    let mut output = Vec::new();
    session
        .write_file_to(&archive, files[1], &mut output)
        .unwrap();
    assert_eq!(output, next);

    // Prove a mistakenly committed failed dictionary cannot pass the fixture.
    session
        .write_file_to(&failed_archive, &valid, &mut std::io::sink())
        .unwrap();
    let error = session
        .write_file_to(&archive, files[1], &mut std::io::sink())
        .unwrap_err();
    assert_eq!(error.kind(), crate::ErrorKind::ChecksumMismatch);
}

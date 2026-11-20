use super::support::{rar50_entry, CollectWriter};
use rars::rar50::*;

use rars::crc32::Crc32;
use rars::{ArchiveVersion, Error, FeatureSet};
use std::{cell::RefCell, rc::Rc};

#[test]
fn parallel_extraction_emits_a_bounded_batch_before_decoding_the_next() {
    let bytes = Rar50Writer::new(
        WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only())
            .with_compression_level(0),
    )
    .entries([
        rar50_entry(b"first", &[1; 64]),
        rar50_entry(b"second", &[2; 64]),
    ])
    .finish()
    .unwrap();
    let mut archive = Archive::parse_owned(bytes).unwrap();
    for block in &mut archive.blocks {
        if let rars::rar50::Block::File(file) = block {
            if file.name == b"second" {
                file.hash = None;
                file.data_crc32 = Some(0);
            }
        }
    }
    let mut opened = Vec::new();
    let error = archive
        .extract_to_parallel_buffered(
            rars::ArchiveReadOptions::default().with_rar50_buffered_decode_limit(64),
            |meta| {
                opened.push(meta.name.clone());
                Ok(Box::new(std::io::sink()))
            },
        )
        .unwrap_err();
    assert!(matches!(error, Error::AtEntry { source, .. }
        if matches!(*source, Error::Crc32Mismatch { .. })));
    assert_eq!(opened, vec![b"first".to_vec()]);
}

#[test]
fn parallel_extraction_handles_empty_entries_and_small_limits() {
    let bytes = Rar50Writer::new(
        WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::store_only())
            .with_compression_level(0),
    )
    .entries([rar50_entry(b"empty", &[]), rar50_entry(b"data", &[1; 64])])
    .finish()
    .unwrap();
    let archive = Archive::parse_owned(bytes).unwrap();
    for limit in [0, 32, 64, 128] {
        let mut opened = Vec::new();
        archive
            .extract_to_parallel_buffered(
                rars::ArchiveReadOptions::default().with_rar50_buffered_decode_limit(limit),
                |meta| {
                    opened.push(meta.name.clone());
                    Ok(Box::new(std::io::sink()))
                },
            )
            .unwrap();
        assert_eq!(opened, vec![b"empty".to_vec(), b"data".to_vec()]);
    }
}

#[test]
fn direct_streaming_extracts_compressed_zero_run() {
    let data = vec![0; 16 * 1024];
    let bytes = Rar50Writer::new(WriterOptions::new(
        ArchiveVersion::Rar50,
        FeatureSet::store_only(),
    ))
    .entries([rar50_entry(b"zeroes", &data)])
    .finish()
    .unwrap();
    let archive = Archive::parse_owned(bytes).unwrap();
    assert!(!archive.files().next().unwrap().is_stored());
    let output = Rc::new(RefCell::new(Vec::new()));
    archive
        .extract_to(
            rars::ArchiveReadOptions::new().with_rar50_buffered_decode_limit(0),
            |_| Ok(Box::new(CollectWriter(output.clone()))),
        )
        .unwrap();
    assert_eq!(*output.borrow(), data);
}

#[test]
fn streaming_crc32_zero_advance_matches_byte_update() {
    let mut bytewise = Crc32::new();
    bytewise.update(&vec![0; 100_000]);

    let mut skipped = Crc32::new();
    skipped.update_zeroes(100_000);

    assert_eq!(skipped.finish(), bytewise.finish());
}

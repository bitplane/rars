#![cfg(feature = "write")]

#[path = "support/volume_size.rs"]
mod volume_size;
use rars::rar50::{Archive, Block};
use rars::{ArchiveReader, ArchiveVersion, Builder};

const PRODUCER: &[u8] =
    concat!("rars/", env!("CARGO_PKG_VERSION"), "\nmarker-schema=1\n").as_bytes();

fn assert_marker(archive: &Archive) {
    assert!(
        matches!(&archive.blocks[0], Block::Service(marker) if marker.name == b"RARS"),
        "producer must precede files and user comments"
    );
    check_marker(archive, 0);
}

/// Later volumes start with their split member, as RAR writes them, and carry
/// the producer after their files.
fn assert_volume_marker(archive: &Archive, index: usize) {
    if index == 0 {
        return assert_marker(archive);
    }
    assert!(matches!(&archive.blocks[0], Block::File(_)));
    let at = archive
        .blocks
        .iter()
        .position(|block| matches!(block, Block::Service(marker) if marker.name == b"RARS"))
        .expect("every volume has a producer record");
    assert!(archive.blocks[at..]
        .iter()
        .all(|block| !matches!(block, Block::File(_))));
    check_marker(archive, at);
}

fn check_marker(archive: &Archive, at: usize) {
    let Block::Service(marker) = &archive.blocks[at] else {
        unreachable!("checked by the caller");
    };
    assert_eq!(marker.name, b"RARS");
    assert_eq!(marker.block.flags, 6);
    assert_eq!(marker.block.extra_area_size, None);
    assert_eq!(marker.compression_info, 0);
    assert!(!marker.encrypted);
    assert_eq!(archive.services().filter(|s| s.name == b"RARS").count(), 1);
    let mut data = Vec::new();
    marker.write_to(archive, None, &mut data).unwrap();
    assert_eq!(data, PRODUCER);
}

#[test]
fn producer_is_not_a_member_or_a_user_comment_including_empty_archives() {
    for version in [ArchiveVersion::Rar50, ArchiveVersion::Rar70] {
        for store in [false, true] {
            for empty in [false, true] {
                let mut builder = Builder::new(version)
                    .store(store)
                    .comment(Some(b"user comment".to_vec()));
                if !empty {
                    builder
                        .add_bytes(b"file".to_vec(), b"payload".to_vec(), None, None)
                        .unwrap();
                }
                let archive = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
                assert_marker(archive.as_rar50().unwrap());
                assert_eq!(archive.members().count(), usize::from(!empty));
                assert_eq!(
                    archive.comment(None).unwrap(),
                    Some(b"user comment".to_vec())
                );
                archive.test(None).unwrap();
                assert!(archive.rewrite_preservation_issues().is_empty());
            }
        }
    }
}

#[test]
fn every_volume_has_an_independent_producer_record() {
    for version in [ArchiveVersion::Rar50, ArchiveVersion::Rar70] {
        let mut builder = Builder::new(version).store(true);
        builder
            .add_bytes(b"file".to_vec(), vec![42; 49], None, None)
            .unwrap();
        let volumes = volume_size::sized_for_payload(16, |size| {
            builder.clone().volume_size(Some(size)).build_volumes(None)
        })
        .unwrap();
        assert!(volumes.len() > 1);
        for (index, volume) in volumes.iter().enumerate() {
            assert_volume_marker(&Archive::parse(volume).unwrap(), index);
        }
    }
}

#[cfg(feature = "encryption")]
#[test]
fn encrypted_headers_keep_producer_payload_public_and_rewritable() {
    for version in [ArchiveVersion::Rar50, ArchiveVersion::Rar70] {
        let mut builder = Builder::new(version)
            .store(true)
            .password(Some(b"secret".to_vec()))
            .header_encryption(true);
        builder
            .add_bytes(b"private-name".to_vec(), vec![42; 49], None, None)
            .unwrap();
        let bytes = builder.to_bytes().unwrap();
        assert!(bytes.windows(PRODUCER.len()).any(|part| part == PRODUCER));
        assert!(!bytes
            .windows(b"private-name".len())
            .any(|part| part == b"private-name"));
        let archive = Archive::parse_with_password(&bytes, Some(b"secret")).unwrap();
        assert_marker(&archive);
        assert!(rars::Archive::Rar50Plus(archive)
            .preserving_builder(Some(b"secret"))
            .is_ok());
        for (index, volume) in volume_size::sized_for_payload(16, |size| {
            builder.clone().volume_size(Some(size)).build_volumes(None)
        })
        .unwrap()
        .iter()
        .enumerate()
        {
            assert_volume_marker(
                &Archive::parse_with_password(volume, Some(b"secret")).unwrap(),
                index,
            );
        }
    }
}

// Replace only the version/schema bytes, updating both CRCs as a different
// producer version would. The fixture uses one-byte sizes and stored data.
fn replace_marker(mut bytes: Vec<u8>, mutate: impl FnOnce(&mut [u8])) -> Vec<u8> {
    let archive = Archive::parse(&bytes).unwrap();
    let marker = archive.services().find(|s| s.name == b"RARS").unwrap();
    let range = marker.block.data_range.clone();
    mutate(&mut bytes[range.clone()]);
    let crc = rars::crc32::crc32(&bytes[range.clone()]);
    let crc_at = marker.block.header_range.start + 3;
    assert_eq!(
        &bytes[crc_at..crc_at + 4],
        &marker.data_crc32.unwrap().to_le_bytes()
    );
    bytes[crc_at..crc_at + 4].copy_from_slice(&crc.to_le_bytes());
    let start = marker.block.offset;
    let crc = rars::crc32::crc32(&bytes[start + 4..range.start]);
    bytes[start..start + 4].copy_from_slice(&crc.to_le_bytes());
    bytes
}

#[test]
fn rewrite_replaces_old_producer_and_rejects_unknown_or_damaged_records() {
    let builder = Builder::new(ArchiveVersion::Rar50).store(true);
    let bytes = builder.to_bytes().unwrap();
    let old = replace_marker(bytes.clone(), |data| {
        for byte in &mut data[5..5 + env!("CARGO_PKG_VERSION").len()] {
            if byte.is_ascii_digit() {
                *byte = b'0';
            }
        }
    });
    let source = ArchiveReader::read_owned(old).unwrap();
    let mut rewrite = source.preserving_builder(None).unwrap();
    rewrite
        .add_bytes(b"new".to_vec(), b"new data".to_vec(), None, None)
        .unwrap();
    let rewritten = ArchiveReader::read_owned(rewrite.to_bytes().unwrap()).unwrap();
    assert_marker(rewritten.as_rar50().unwrap());
    assert_eq!(
        rewritten.read_member(b"new", None).unwrap().unwrap(),
        b"new data"
    );

    let unknown = replace_marker(bytes.clone(), |data| {
        let end = data.len();
        data[end - 2] = b'2';
    });
    assert!(ArchiveReader::read_owned(unknown)
        .unwrap()
        .preserving_builder(None)
        .is_err());
    let mut damaged = bytes;
    let archive = Archive::parse(&damaged).unwrap();
    let offset = archive.services().next().unwrap().block.data_range.start;
    damaged[offset] ^= 1;
    assert!(ArchiveReader::read_owned(damaged)
        .unwrap()
        .preserving_builder(None)
        .is_err());

    let mut duplicate = rewritten.clone();
    let rars::Archive::Rar50Plus(raw) = &mut duplicate else {
        unreachable!()
    };
    raw.blocks.insert(0, raw.blocks[0].clone());
    assert!(duplicate.preserving_builder(None).is_err());
}

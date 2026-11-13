#![cfg(feature = "write")]

#[path = "support/volume_size.rs"]
mod volume_size;
use rars::rar15_40::{Archive, Block, NewSubKind};
use rars::{ArchiveReader, ArchiveVersion, Builder};

const DATA: &[u8] = concat!("rars/", env!("CARGO_PKG_VERSION"), "\nmarker-schema=1\n").as_bytes();

fn marker(archive: &Archive) {
    let index = usize::from(matches!(archive.blocks.first(), Some(Block::Comment(_))));
    assert!(
        matches!(&archive.blocks[index], Block::NewSub(sub) if sub.file.name == b"RARS"),
        "producer must follow any old-style comment and precede files"
    );
    check_marker(archive, index);
}

/// Later volumes start with their split member, as RAR writes them, and carry
/// the producer after it.
fn volume_marker(archive: &Archive, index: usize) {
    if index == 0 {
        return marker(archive);
    }
    assert!(matches!(&archive.blocks[0], Block::File(_)));
    let at = archive
        .blocks
        .iter()
        .position(|block| matches!(block, Block::NewSub(sub) if sub.file.name == b"RARS"))
        .expect("every volume has a producer record");
    assert!(archive.blocks[at..]
        .iter()
        .all(|block| !matches!(block, Block::File(_))));
    check_marker(archive, at);
}

fn check_marker(archive: &Archive, at: usize) {
    let Block::NewSub(sub) = &archive.blocks[at] else {
        unreachable!("checked by the caller");
    };
    assert_eq!(sub.file.name, b"RARS");
    assert_eq!(sub.file.block.flags, 0xc000);
    assert_eq!(sub.file.block.head_size, 36);
    assert_eq!(sub.file.method, 0x30);
    assert!(!sub.file.is_encrypted());
    assert_eq!(
        archive
            .new_subs()
            .filter(|sub| sub.file.name == b"RARS")
            .count(),
        1
    );
    let mut data = Vec::new();
    sub.file.write_to(archive, None, &mut data).unwrap();
    assert_eq!(data, DATA);
}

#[test]
fn legacy_producer_preserves_members_comments_and_format_requirement() {
    for version in [
        ArchiveVersion::Rar15,
        ArchiveVersion::Rar20,
        ArchiveVersion::Rar29,
        ArchiveVersion::Rar30,
        ArchiveVersion::Rar40,
    ] {
        for store in [false, true] {
            for empty in [false, true] {
                for comment in [None, Some(b"user comment".to_vec())] {
                    let mut builder = Builder::new(version).store(store).comment(comment.clone());
                    if !empty {
                        builder
                            .add_bytes(b"file".to_vec(), b"payload".to_vec(), None, None)
                            .unwrap();
                    }
                    let bytes = if empty {
                        rars::rar15_40::write_stored_archive_with_comment(
                            &[],
                            rars::rar15_40::WriterOptions::new(
                                version,
                                rars::FeatureSet::store_only(),
                            ),
                            comment.as_deref(),
                        )
                        .unwrap()
                    } else {
                        builder.to_bytes().unwrap()
                    };
                    let archive = ArchiveReader::read_owned(bytes).unwrap();
                    marker(archive.as_rar15_40().unwrap());
                    let expected_unp_ver = match version {
                        ArchiveVersion::Rar15 => 15,
                        ArchiveVersion::Rar20 => 20,
                        _ => 29,
                    };
                    assert_eq!(
                        archive
                            .as_rar15_40()
                            .unwrap()
                            .new_subs()
                            .next()
                            .unwrap()
                            .file
                            .unp_ver,
                        expected_unp_ver
                    );
                    assert_eq!(archive.members().count(), usize::from(!empty));
                    assert_eq!(archive.comment(None).unwrap(), comment);
                    archive.test(None).unwrap();
                    if empty {
                        // Legacy builders already refuse zero-member output.
                        assert!(archive.preserving_builder(None).is_err());
                        continue;
                    }
                    let mut rewrite = archive
                        .preserving_builder(None)
                        .unwrap()
                        .comment(comment.clone());
                    rewrite
                        .add_bytes(b"new".to_vec(), b"new data".to_vec(), None, None)
                        .unwrap();
                    let rewritten = rewrite.to_bytes().unwrap();
                    let parsed = Archive::parse(&rewritten).unwrap();
                    marker(&parsed);
                    assert_eq!(parsed.archive_comment().unwrap(), comment);
                    if matches!(
                        version,
                        ArchiveVersion::Rar15 | ArchiveVersion::Rar20 | ArchiveVersion::Rar29
                    ) {
                        assert_eq!(parsed.files().next().unwrap().unp_ver, expected_unp_ver);
                        assert_eq!(
                            parsed.new_subs().next().unwrap().file.unp_ver,
                            expected_unp_ver
                        );
                        assert!(!parsed
                            .new_subs()
                            .any(|sub| sub.kind == NewSubKind::ArchiveComment));
                    }
                }
            }
        }
    }
}

#[test]
fn each_legacy_volume_has_a_producer() {
    for version in [
        ArchiveVersion::Rar15,
        ArchiveVersion::Rar20,
        ArchiveVersion::Rar29,
        ArchiveVersion::Rar30,
        ArchiveVersion::Rar40,
    ] {
        for store in [false, true] {
            let mut builder = Builder::new(version).store(store);
            builder
                .add_bytes(b"file".to_vec(), (0..128).collect(), None, None)
                .unwrap();
            let volumes = volume_size::sized_for_payload(16, |size| {
                builder.clone().volume_size(Some(size)).build_volumes(None)
            })
            .unwrap();
            assert!(volumes.len() > 1);
            for (index, volume) in volumes.iter().enumerate() {
                volume_marker(&Archive::parse(volume).unwrap(), index);
            }
        }
    }
}

#[cfg(feature = "encryption")]
#[test]
fn encrypted_legacy_headers_leave_only_producer_payload_public() {
    for version in [ArchiveVersion::Rar30, ArchiveVersion::Rar40] {
        let mut builder = Builder::new(version)
            .store(true)
            .password(Some(b"secret".to_vec()))
            .header_encryption(true);
        builder
            .add_bytes(b"private-name".to_vec(), (0..49).collect(), None, None)
            .unwrap();
        let bytes = builder.to_bytes().unwrap();
        assert!(bytes.windows(DATA.len()).any(|part| part == DATA));
        assert!(!bytes
            .windows(b"private-name".len())
            .any(|part| part == b"private-name"));
        let raw = Archive::parse_with_password(&bytes, Some(b"secret")).unwrap();
        marker(&raw);
        assert!(rars::Archive::Rar15To40(raw)
            .preserving_builder(Some(b"secret"))
            .is_ok());
        for (index, volume) in volume_size::sized_for_payload(16, |size| {
            builder.clone().volume_size(Some(size)).build_volumes(None)
        })
        .unwrap()
        .iter()
        .enumerate()
        {
            volume_marker(
                &Archive::parse_with_password(volume, Some(b"secret")).unwrap(),
                index,
            );
        }
    }
}

fn mutate_payload(mut bytes: Vec<u8>, change: impl FnOnce(&mut [u8])) -> Vec<u8> {
    let archive = Archive::parse(&bytes).unwrap();
    let file = &archive
        .new_subs()
        .find(|sub| sub.file.name == b"RARS")
        .unwrap()
        .file;
    let start = file.block.offset;
    change(&mut bytes[file.packed_range.clone()]);
    let crc = rars::crc32::crc32(&bytes[file.packed_range.clone()]);
    bytes[start + 16..start + 20].copy_from_slice(&crc.to_le_bytes());
    let crc =
        rars::crc32::crc32(&bytes[start + 2..start + usize::from(file.block.head_size)]) as u16;
    bytes[start..start + 2].copy_from_slice(&crc.to_le_bytes());
    bytes
}

#[test]
fn legacy_rewrite_replaces_known_producer_and_refuses_ambiguous_records() {
    for version in [
        ArchiveVersion::Rar15,
        ArchiveVersion::Rar20,
        ArchiveVersion::Rar29,
        ArchiveVersion::Rar30,
    ] {
        let mut builder = Builder::new(version).store(true);
        builder
            .add_bytes(b"file".to_vec(), b"payload".to_vec(), None, None)
            .unwrap();
        let bytes = builder.to_bytes().unwrap();
        let old = mutate_payload(bytes.clone(), |data| {
            for byte in &mut data[5..5 + env!("CARGO_PKG_VERSION").len()] {
                if byte.is_ascii_digit() {
                    *byte = b'0';
                }
            }
        });
        let archive = ArchiveReader::read_owned(old).unwrap();
        let mut rewrite = archive.preserving_builder(None).unwrap();
        rewrite
            .add_bytes(b"new".to_vec(), b"new data".to_vec(), None, None)
            .unwrap();
        marker(&Archive::parse(&rewrite.to_bytes().unwrap()).unwrap());
        let unknown = mutate_payload(bytes.clone(), |data| {
            let end = data.len();
            data[end - 2] = b'2';
        });
        assert!(ArchiveReader::read_owned(unknown)
            .unwrap()
            .preserving_builder(None)
            .is_err());
        let mut damaged = bytes.clone();
        let offset = Archive::parse(&bytes)
            .unwrap()
            .new_subs()
            .next()
            .unwrap()
            .file
            .packed_range
            .start;
        damaged[offset] ^= 1;
        assert!(ArchiveReader::read_owned(damaged)
            .unwrap()
            .preserving_builder(None)
            .is_err());
        for change in 0..8 {
            let mut archive = Archive::parse(&bytes).unwrap();
            match change {
                0 => archive.blocks.insert(0, archive.blocks[0].clone()),
                1 => archive.blocks.swap(0, 1),
                _ => {
                    let Block::NewSub(sub) = &mut archive.blocks[0] else {
                        unreachable!()
                    };
                    match change {
                        2 => sub.file.block.head_size += 1,
                        3 => sub.file.unp_size = 129,
                        4 => sub.file.block.flags |= 8,
                        5 => sub.file.file_crc ^= 1,
                        6 => sub.kind = NewSubKind::ArchiveComment,
                        _ => sub.file.unp_ver = 26,
                    }
                }
            }
            assert!(
                rars::Archive::Rar15To40(archive)
                    .preserving_builder(None)
                    .is_err(),
                "mutation {change}"
            );
        }
    }
}

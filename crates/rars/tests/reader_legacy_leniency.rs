#![cfg(feature = "write")]
//! Issue #489: archives unrar accepts, every member's CRC intact, that rars
//! refused. Zero padding after a member's last code, malformed optional old
//! blocks, and a file that ends in or before a block that follows every member.

use rars::crc32::crc32;
use rars::{Archive, ArchiveReader, ArchiveVersion, Builder, Error, TruncatedBlock};
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/rar15_40")
        .join(name)
}

fn members() -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut state = 489u32;
    let noise: Vec<u8> = (0..5000)
        .map(|_| {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (state >> 24) as u8
        })
        .collect();
    vec![
        (
            b"first.txt".to_vec(),
            b"issue 489 first member\n".repeat(300),
        ),
        (b"second.bin".to_vec(), noise),
    ]
}

fn build(builder: Builder) -> Vec<u8> {
    let mut builder = builder;
    for (name, data) in members() {
        builder.add_bytes(name, data, None, None).unwrap();
    }
    builder.to_bytes().unwrap()
}

struct Shared(Arc<Mutex<Vec<u8>>>);

impl Write for Shared {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Tests every member, then extracts each one by name.
fn verified(archive: &Archive) -> rars::Result<Vec<(Vec<u8>, Vec<u8>)>> {
    archive.test(None)?;
    let entries = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&entries);
    archive.extract_to(None, move |meta| {
        let data = Arc::new(Mutex::new(Vec::new()));
        sink.lock()
            .unwrap()
            .push((meta.name.clone(), Arc::clone(&data)));
        Ok(Box::new(Shared(data)))
    })?;
    let entries = entries.lock().unwrap();
    Ok(entries
        .iter()
        .map(|(name, data)| (name.clone(), data.lock().unwrap().clone()))
        .collect())
}

/// Block offsets in a RAR 1.5-4 archive, by type.
fn legacy_blocks(bytes: &[u8]) -> Vec<(usize, u8)> {
    let mut blocks = Vec::new();
    let mut pos = 7;
    while pos + 7 <= bytes.len() {
        let flags = u16::from_le_bytes([bytes[pos + 3], bytes[pos + 4]]);
        let head_size = usize::from(u16::from_le_bytes([bytes[pos + 5], bytes[pos + 6]]));
        let add_size = if flags & 0x8000 != 0 {
            u32::from_le_bytes(bytes[pos + 7..pos + 11].try_into().unwrap()) as usize
        } else {
            0
        };
        blocks.push((pos, bytes[pos + 2]));
        pos += head_size + add_size;
    }
    blocks
}

fn write_header_crc(header: &mut [u8], head_size: usize) {
    let crc = (crc32(&header[2..head_size]) & 0xffff) as u16;
    header[..2].copy_from_slice(&crc.to_le_bytes());
}

/// Appends `padding` to the packed data of the file header at `pos`.
fn pad_legacy_member(bytes: &mut Vec<u8>, pos: usize, padding: &[u8]) {
    let head_size = usize::from(u16::from_le_bytes([bytes[pos + 5], bytes[pos + 6]]));
    let pack_size = u32::from_le_bytes(bytes[pos + 7..pos + 11].try_into().unwrap());
    let end = pos + head_size + pack_size as usize;
    bytes.splice(end..end, padding.iter().copied());
    let pack_size = pack_size + padding.len() as u32;
    bytes[pos + 7..pos + 11].copy_from_slice(&pack_size.to_le_bytes());
    write_header_crc(&mut bytes[pos..], head_size);
}

#[test]
fn rar29_lz_members_may_end_in_whole_zero_bytes() {
    let bytes = std::fs::read(fixture("zero_padding/rar29.rar")).unwrap();
    let archive = ArchiveReader::read(&bytes).unwrap();
    let entries = verified(&archive).unwrap();
    let mut first = (0..=255u8).collect::<Vec<_>>().repeat(6);
    first.extend_from_slice(&b"RAR 2.9 member without an end-of-block code\n".repeat(4));
    let second = (32..127u8).collect::<Vec<_>>().repeat(30);
    assert_eq!(
        entries,
        [
            (b"first.bin".to_vec(), first),
            (b"second.txt".to_vec(), second)
        ]
    );

    // A set bit in the padding is more stream, not padding.
    let rars::Archive::Rar15To40(parsed) = &archive else {
        panic!("RAR 2.9 archive");
    };
    let last_padding_byte = parsed.files().next().unwrap().packed_range.end - 1;
    let mut damaged = bytes.clone();
    damaged[last_padding_byte] = 0x01;
    let archive = ArchiveReader::read(&damaged).unwrap();
    let error = archive.test(None).unwrap_err();
    assert_eq!(
        *error.root_cause(),
        Error::Codec(rars::codec::Error::InvalidData(
            "RAR 2.9 LZ member has trailing data"
        )),
        "{error}"
    );
}

/// RAR 1.5 and 2.0 have no end-of-file code, so whole zero bytes after the
/// last code were already only padding there. They stay that way, solid too.
#[test]
fn rar15_and_rar20_members_may_end_in_whole_zero_bytes() {
    for version in [ArchiveVersion::Rar15, ArchiveVersion::Rar20] {
        for solid in [false, true] {
            let mut bytes = build(Builder::new(version).solid(solid));
            // The compressed members: the noise may be stored.
            let files: Vec<_> = legacy_blocks(&bytes)
                .into_iter()
                .filter(|&(pos, head_type)| head_type == 0x74 && bytes[pos + 25] != 0x30)
                .map(|(pos, _)| pos)
                .collect();
            assert!(!files.is_empty(), "{version:?} solid={solid}");
            // Last first, so the earlier offsets stay put.
            for (index, &pos) in files.iter().enumerate().rev() {
                pad_legacy_member(&mut bytes, pos, &vec![0; 1 + 15 * index]);
            }
            let archive = ArchiveReader::read(&bytes).unwrap();
            assert_eq!(
                verified(&archive).unwrap(),
                members(),
                "{version:?} solid={solid}"
            );
        }
    }
}

/// A RAR 1.5-4 block with its header CRC written.
fn legacy_block(head_type: u8, head_size: u16, add_size: Option<u32>) -> Vec<u8> {
    let mut block = vec![0; usize::from(head_size)];
    block[2] = head_type;
    block[5..7].copy_from_slice(&head_size.to_le_bytes());
    if let Some(add_size) = add_size {
        block[3..5].copy_from_slice(&0x8000u16.to_le_bytes());
        block[7..11].copy_from_slice(&add_size.to_le_bytes());
    }
    if head_type == 0x78 && head_size >= 26 {
        // One parity sector over two blocks: 2 * 2 + 512 bytes of data.
        block[11] = 1;
        block[12..14].copy_from_slice(&1u16.to_le_bytes());
        block[14..18].copy_from_slice(&2u32.to_le_bytes());
        block[18..26].copy_from_slice(b"Protect!");
    }
    write_header_crc(&mut block, usize::from(head_size));
    block.resize(block.len() + add_size.unwrap_or(0) as usize, 0);
    block
}

#[test]
fn malformed_optional_old_blocks_are_skipped_with_a_warning() {
    for version in [ArchiveVersion::Rar20, ArchiveVersion::Rar29] {
        let whole = build(Builder::new(version));
        let blocks = legacy_blocks(&whole);
        let first_file = blocks.iter().find(|block| block.1 == 0x74).unwrap().0;
        // Before the end block, where there is one.
        let tail = blocks
            .iter()
            .find(|block| block.1 == 0x7b)
            .map_or(whole.len(), |block| block.0);
        for (name, block, at, reason) in [
            (
                "short authenticity block",
                legacy_block(0x76, 20, None),
                first_file,
                "RAR legacy authenticity block is too short",
            ),
            (
                "short signature block",
                legacy_block(0x79, 30, None),
                first_file,
                "RAR legacy authenticity block is too short",
            ),
            (
                "short recovery block",
                legacy_block(0x78, 20, Some(8)),
                tail,
                "RAR 2.x recovery header size is invalid",
            ),
            (
                "recovery block with short data",
                legacy_block(0x78, 26, Some(2 * 2 + 512 - 16)),
                tail,
                "RAR 2.x recovery data size does not match header",
            ),
        ] {
            let context = format!("{version:?} {name}");
            let mut bytes = whole.clone();
            bytes.splice(at..at, block);
            let archive = ArchiveReader::read(&bytes).expect(&context);
            let skipped = archive.skipped_blocks();
            assert_eq!(skipped.len(), 1, "{context}");
            assert_eq!(skipped[0].offset, at as u64, "{context}");
            assert_eq!(skipped[0].reason, reason, "{context}");
            assert_eq!(archive.truncation(), None, "{context}");
            assert_eq!(verified(&archive).unwrap(), members(), "{context}");
        }
        let archive = ArchiveReader::read(&whole).unwrap();
        assert!(archive.skipped_blocks().is_empty());
    }
}

#[test]
fn a_cut_after_every_member_says_whether_it_can_have_lost_one() {
    let builder = Builder::new(ArchiveVersion::Rar50)
        .archive_metadata(None, false, true)
        .unwrap();
    let with_qo = build(builder);
    let rars::Archive::Rar50Plus(whole) = ArchiveReader::read(&with_qo).unwrap() else {
        panic!("RAR 5 archive");
    };
    let qo = whole
        .services()
        .find(|service| service.name == b"QO")
        .unwrap()
        .block
        .clone();
    let qo_data = qo.data_range.start + qo.data_range.len() / 2;
    let qo = qo.offset;
    let end = whole
        .blocks
        .iter()
        .find_map(|block| match block {
            rars::rar50::Block::End(end) => Some(end.block.offset),
            _ => None,
        })
        .unwrap();
    let last_member = whole.files().last().unwrap().block.offset;

    let cases: [(usize, TruncatedBlock, bool, bool); 4] = [
        // The quick-open block before it follows every member.
        (end, TruncatedBlock::End, false, true),
        (qo_data, TruncatedBlock::Service(b"QO".to_vec()), true, true),
        // The locator says the quick-open block was due here.
        (qo, TruncatedBlock::Service(b"QO".to_vec()), false, true),
        (end + 6, TruncatedBlock::End, true, true),
    ];
    for (cut, block, started, complete) in cases {
        let context = format!("cut at {cut} of {}", with_qo.len());
        let archive = ArchiveReader::read(&with_qo[..cut]).expect(&context);
        let truncation = archive.truncation().expect(&context);
        assert_eq!(truncation.block, block, "{context}");
        assert_eq!(truncation.started, started, "{context}");
        assert_eq!(truncation.members_complete, complete, "{context}");
        assert_eq!(verified(&archive).unwrap(), members(), "{context}");
    }
    // The locator says the quick-open block comes later, so a member may be missing.
    assert!(ArchiveReader::read(&with_qo[..last_member]).is_err());

    // A volume's end block says whether another volume follows.
    for version in [ArchiveVersion::Rar29, ArchiveVersion::Rar50] {
        let volumes = {
            let mut builder = Builder::new(version).store(true).volume_size(Some(4096));
            for (name, data) in members() {
                builder.add_bytes(name, data, None, None).unwrap();
            }
            builder.build_volumes(None).unwrap()
        };
        assert!(volumes.len() > 1, "{version:?}");
        let last = volumes.last().unwrap();
        let cut = &last[..last.len() - 1];
        let archive = ArchiveReader::read(cut).unwrap();
        let truncation = archive.truncation().expect("cut volume");
        assert_eq!(truncation.block, TruncatedBlock::End, "{version:?}");
        assert!(!truncation.members_complete, "{version:?}");

        // The same cut in a lone archive can't have lost a member.
        let lone = build(Builder::new(version).store(true));
        let archive = ArchiveReader::read(&lone[..lone.len() - 1]).unwrap();
        let truncation = archive.truncation().expect("cut archive");
        assert_eq!(truncation.block, TruncatedBlock::End, "{version:?}");
        assert!(truncation.members_complete, "{version:?}");
    }
}

#![cfg(feature = "write")]

use rars::{ArchiveVersion, Builder};

// As RAR 3.00 writes them: the last volume or a lone archive, then one with more to come.
const END_LAST: [u8; 7] = [0xc4, 0x3d, 0x7b, 0x00, 0x40, 0x07, 0x00];
const END_MORE: [u8; 7] = [0xa1, 0x5a, 0x7b, 0x01, 0x40, 0x07, 0x00];

const WITH_END_BLOCK: [ArchiveVersion; 3] = [
    ArchiveVersion::Rar29,
    ArchiveVersion::Rar30,
    ArchiveVersion::Rar40,
];

fn builder(version: ArchiveVersion, stored: bool) -> Builder {
    let mut builder = Builder::new(version).store(stored);
    let mut state = 0x9e37_79b9u32;
    let data: Vec<u8> = (0..20_000)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect();
    builder
        .add_bytes(b"file".to_vec(), data, None, None)
        .unwrap();
    builder
}

#[test]
fn rar29_to_40_archives_end_with_a_last_end_block() {
    for version in WITH_END_BLOCK {
        for stored in [true, false] {
            let archive = builder(version, stored).to_bytes().unwrap();
            assert!(archive.ends_with(&END_LAST), "{version:?} stored={stored}");
        }
    }
}

#[test]
fn rar29_to_40_volumes_mark_every_end_block_but_the_last() {
    for version in WITH_END_BLOCK {
        for stored in [true, false] {
            let volumes = builder(version, stored)
                .volume_size(Some(4096))
                .build_volumes(None)
                .unwrap();
            assert!(volumes.len() > 2, "{version:?} stored={stored}");
            let (last, rest) = volumes.split_last().unwrap();
            for volume in rest {
                assert!(volume.ends_with(&END_MORE), "{version:?} stored={stored}");
            }
            assert!(last.ends_with(&END_LAST), "{version:?} stored={stored}");
        }
    }
}

#[test]
fn rar15_and_20_output_ends_in_payload_like_real_rar_2() {
    for version in [ArchiveVersion::Rar15, ArchiveVersion::Rar20] {
        for stored in [true, false] {
            let archive = builder(version, stored).to_bytes().unwrap();
            let volumes = builder(version, stored)
                .volume_size(Some(4096))
                .build_volumes(None)
                .unwrap();
            for output in std::iter::once(&archive).chain(&volumes) {
                assert!(
                    !output.ends_with(&END_LAST) && !output.ends_with(&END_MORE),
                    "{version:?} stored={stored}"
                );
            }
        }
    }
}

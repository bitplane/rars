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
fn rar29_to_40_volumes_end_as_rar_3_93_volumes_do() {
    // Twenty bytes: the next-volume flag on all but the last, then the CRC32 of
    // every byte before the block, the volume number from 0, and seven reserved
    // zero bytes, each with its flag.
    for version in WITH_END_BLOCK {
        for stored in [true, false] {
            let volumes = builder(version, stored)
                .volume_size(Some(4096))
                .build_volumes(None)
                .unwrap();
            assert!(volumes.len() > 2, "{version:?} stored={stored}");
            for (index, volume) in volumes.iter().enumerate() {
                let (body, end) = volume.split_at(volume.len() - 20);
                let more = u16::from(index + 1 < volumes.len());
                let header_crc = rars::crc32::crc32(&end[2..]) as u16;
                assert_eq!(
                    (
                        u16::from_le_bytes([end[0], end[1]]),
                        end[2],
                        u16::from_le_bytes([end[3], end[4]]),
                        u16::from_le_bytes([end[5], end[6]]),
                        u32::from_le_bytes([end[7], end[8], end[9], end[10]]),
                        u16::from_le_bytes([end[11], end[12]]),
                        &end[13..],
                    ),
                    (
                        header_crc,
                        0x7b,
                        0x400e | more,
                        20,
                        rars::crc32::crc32(body),
                        index as u16,
                        &[0u8; 7][..],
                    ),
                    "{version:?} stored={stored} volume {index}"
                );
            }
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

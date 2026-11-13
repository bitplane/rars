#![cfg(all(feature = "write", feature = "encryption", feature = "recovery"))]
//! What RAR 7.12 checks in a password-protected RAR 5 set that rars writes.

use rars::rar50::{Archive, Block};
use rars::{ArchiveVersion, Builder};

fn noise(len: usize) -> Vec<u8> {
    let mut state = 0x2545_f491u32;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect()
}

fn build(header_encryption: bool, volume_size: Option<usize>) -> Vec<Vec<u8>> {
    let mut builder = Builder::new(ArchiveVersion::Rar50)
        .store(true)
        .password(Some(b"pw".to_vec()))
        .header_encryption(header_encryption)
        .recovery_percent(Some(5))
        .volume_size(volume_size);
    builder
        .add_bytes(b"data.bin".to_vec(), noise(150_000), None, None)
        .unwrap();
    match volume_size {
        Some(_) => builder.build_volumes(None).unwrap(),
        None => {
            let mut bytes = Vec::new();
            builder
                .write_to(&mut bytes, &rars::WriterResources::default(), None)
                .unwrap();
            vec![bytes]
        }
    }
}

#[test]
fn the_locator_counts_from_the_main_header() {
    // With encrypted headers the main header sits after the encryption header,
    // not straight after the signature; RAR 7.12 reports a corrupt recovery
    // record when the offset is counted from the signature instead.
    for header_encryption in [false, true] {
        for volume_size in [None, Some(64 * 1024)] {
            for volume in build(header_encryption, volume_size) {
                let archive = Archive::parse_with_password(&volume, Some(b"pw")).unwrap();
                let offset = archive
                    .main
                    .locator()
                    .unwrap()
                    .recovery_record_offset
                    .unwrap();
                let recovery = archive
                    .services()
                    .find(|service| service.name == b"RR")
                    .unwrap();
                assert_eq!(
                    archive.main.block.offset as u64 + offset,
                    recovery.block.offset as u64,
                    "header_encryption={header_encryption} volumes={volume_size:?}"
                );
            }
        }
    }
}

#[test]
fn only_a_split_member_s_last_part_marks_its_checksums_as_macs() {
    // Earlier parts carry the plain CRC32 of their ciphertext, so a reader
    // told they are MACs computes a MAC and reports a packed data checksum error.
    for header_encryption in [false, true] {
        let volumes = build(header_encryption, Some(64 * 1024));
        assert!(volumes.len() > 2);
        for (index, volume) in volumes.iter().enumerate() {
            let archive = Archive::parse_with_password(volume, Some(b"pw")).unwrap();
            for block in &archive.blocks {
                let Block::File(file) = block else { continue };
                let last = index + 1 == volumes.len();
                let mac = file.encryption.as_ref().unwrap().flags & 0x0002 != 0;
                assert_eq!(mac, last, "volume {} of {}", index + 1, volumes.len());
                if !last {
                    let packed = file.packed_data(&archive).unwrap();
                    assert_eq!(file.data_crc32, Some(rars::crc32::crc32(&packed)));
                }
            }
        }
    }
}

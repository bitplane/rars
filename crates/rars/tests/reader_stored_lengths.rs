#![cfg(feature = "write")]

use rars::{Archive, ArchiveReader, ArchiveVersion, Builder, Error};
#[path = "support/scratch.rs"]
mod scratch;

fn stored(version: ArchiveVersion, encrypted: bool, volumes: bool) -> Vec<Vec<u8>> {
    let mut builder = Builder::new(version)
        .store(true)
        .password((encrypted && !volumes).then(|| b"secret".to_vec()));
    if volumes {
        builder = builder.volume_size(Some(128));
    }
    builder
        .add_bytes(b"zero.bin".to_vec(), vec![0; 256], None, None)
        .unwrap();
    if volumes {
        let mut volumes = builder.build_volumes(None).unwrap();
        if encrypted {
            // The writer does not emit old-format encrypted volume sets. Form
            // one by splitting the legitimate single-member ciphertext while
            // retaining continuous cipher state across the volume boundaries.
            let bytes = stored(version, true, false).pop().unwrap();
            let archive = rars::rar13::Archive::parse(&bytes).unwrap();
            let encrypted_data = &bytes[archive.entries[0].packed_range.clone()];
            let mut position = 0;
            for volume in &mut volumes {
                let archive = rars::rar13::Archive::parse(volume).unwrap();
                let range = archive.entries[0].packed_range.clone();
                let len = range.len();
                volume[range].copy_from_slice(&encrypted_data[position..position + len]);
                let file_start = usize::from(archive.main.head_size);
                volume[file_start + 17] |= 0x04;
                position += len;
            }
            assert_eq!(position, encrypted_data.len());
        }
        volumes
    } else {
        vec![builder.to_bytes().unwrap()]
    }
}

#[test]
fn rar13_stored_members_reject_incorrect_declared_lengths_even_when_checksum_matches() {
    for version in [ArchiveVersion::Rar13, ArchiveVersion::Rar14] {
        for encrypted in [false, true] {
            if encrypted && !cfg!(feature = "encryption") {
                continue;
            }
            let original = stored(version, encrypted, false).pop().unwrap();
            let password = encrypted.then_some(b"secret".as_slice());
            for declared in [0u32, 1, 255, 257] {
                let mut malformed = original.clone();
                let file_start = usize::from(u16::from_le_bytes([malformed[4], malformed[5]]));
                malformed[file_start + 4..file_start + 8].copy_from_slice(&declared.to_le_bytes());
                let archive = ArchiveReader::read_owned(malformed).unwrap();
                assert!(
                    archive.read_member_at(0, password).is_err(),
                    "{version:?}, encrypted={encrypted}, declared={declared}"
                );
                if let Archive::Rar13(archive) = archive {
                    let error = archive.entries[0]
                        .write_to(&archive, password, &mut std::io::sink())
                        .unwrap_err();
                    assert!(matches!(error.root_cause(), Error::InvalidHeader(_)));
                }
            }
        }
    }
}

#[test]
fn rar13_stored_path_sources_reject_short_successful_copies() {
    let scratch = scratch::case("rar13-truncated-stored-source");
    for version in [ArchiveVersion::Rar13, ArchiveVersion::Rar14] {
        let original = stored(version, false, false).pop().unwrap();
        let path = scratch.join("archive.rar");
        std::fs::write(&path, &original).unwrap();
        let archive = ArchiveReader::read_path(&path).unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len((original.len() - 255) as u64)
            .unwrap();
        let error = archive.read_member_at(0, None).unwrap_err();
        assert!(matches!(
            error.root_cause(),
            Error::Io(io) if io.kind == std::io::ErrorKind::UnexpectedEof
        ));
    }
}

#[test]
fn rar13_split_stored_members_verify_reassembled_length() {
    for version in [ArchiveVersion::Rar13, ArchiveVersion::Rar14] {
        for encrypted in [false, true] {
            if encrypted && !cfg!(feature = "encryption") {
                continue;
            }
            let mut bytes = stored(version, encrypted, true);
            assert!(bytes.len() > 1);
            let valid: Vec<_> = bytes
                .iter()
                .map(|bytes| ArchiveReader::read(bytes).unwrap())
                .collect();
            let password = encrypted.then_some(b"secret".as_slice());
            assert_eq!(
                rars::read_volume_member_at(&valid, 0, password)
                    .unwrap()
                    .unwrap(),
                vec![0; 256]
            );
            let last = bytes.last_mut().unwrap();
            let file_start = usize::from(u16::from_le_bytes([last[4], last[5]]));
            last[file_start + 4..file_start + 8].copy_from_slice(&1u32.to_le_bytes());
            let archives: Vec<_> = bytes
                .into_iter()
                .map(|bytes| ArchiveReader::read_owned(bytes).unwrap())
                .collect();
            assert!(rars::read_volume_member_at(&archives, 0, password).is_err());
        }
    }
}

#[test]
fn rar13_split_stored_path_sources_reject_truncation() {
    let scratch = scratch::case("rar13-truncated-split-stored-source");
    for version in [ArchiveVersion::Rar13, ArchiveVersion::Rar14] {
        for encrypted in [false, true] {
            if encrypted && !cfg!(feature = "encryption") {
                continue;
            }
            let bytes = stored(version, encrypted, true);
            let archives: Vec<_> = bytes
                .iter()
                .enumerate()
                .map(|(index, bytes)| {
                    let path = scratch.join(format!("part-{index}.rar"));
                    std::fs::write(&path, bytes).unwrap();
                    ArchiveReader::read_path(&path).unwrap()
                })
                .collect();
            let index = bytes.len() - 1;
            let path = scratch.join(format!("part-{index}.rar"));
            std::fs::OpenOptions::new()
                .write(true)
                .open(path)
                .unwrap()
                .set_len((bytes[index].len() - 1) as u64)
                .unwrap();
            let password = encrypted.then_some(b"secret".as_slice());
            assert!(rars::read_volume_member_at(&archives, 0, password).is_err());
        }
    }
}

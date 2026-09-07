use rars::{Archive, ArchiveReader, ArchiveVersion, Builder, ErrorKind};

fn mixed(format: ArchiveVersion, solid: bool, stored: bool) -> Archive {
    let mut builder = Builder::new(format).solid(solid).store(stored);
    builder
        .add_directory(b"directory".to_vec(), None, None)
        .unwrap();
    for name in [b"first".as_slice(), b"secret", b"last"] {
        builder
            .add_bytes(name.to_vec(), name.repeat(100), None, None)
            .unwrap();
    }
    builder
        .set_entry_encryption(b"secret", Some(b"password".to_vec()), None)
        .unwrap();
    ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap()
}

#[test]
fn plaintext_selection_ignores_independent_encrypted_members_before_and_after_it() {
    for format in ArchiveVersion::ALL {
        for stored in [false, true] {
            let archive = mixed(format, false, stored);
            for (index, name) in [(1, b"first".as_slice()), (3, b"last")] {
                for password in [None, Some(b"wrong".as_slice())] {
                    assert_eq!(
                        archive.read_member(name, password).unwrap().unwrap(),
                        name.repeat(100),
                        "{format}"
                    );
                    assert_eq!(
                        archive.read_member_at(index, password).unwrap().unwrap(),
                        name.repeat(100),
                        "{format}"
                    );
                }
            }
            assert_eq!(
                archive.read_member(b"secret", None).unwrap_err().kind(),
                ErrorKind::PasswordRequired
            );
            assert_eq!(
                archive.read_member_at(2, None).unwrap_err().kind(),
                ErrorKind::PasswordRequired
            );
            assert_eq!(
                archive
                    .read_member(b"secret", Some(b"password"))
                    .unwrap()
                    .unwrap(),
                b"secret".repeat(100)
            );
            assert!(archive.read_member(b"secret", Some(b"wrong")).is_err());
            assert_eq!(
                archive.test(None).unwrap_err().kind(),
                ErrorKind::PasswordRequired
            );
            assert_eq!(archive.read_member(b"missing", None).unwrap(), None);
            assert_eq!(archive.read_member(b"directory", None).unwrap(), None);
            assert_eq!(archive.read_member_at(0, None).unwrap(), None);
            assert_eq!(archive.read_member_at(10, None).unwrap(), None);
        }
    }
}

#[test]
fn solid_selection_stops_after_target_but_verifies_encrypted_predecessors() {
    for format in ArchiveVersion::ALL {
        let archive = mixed(format, true, false);
        assert_eq!(
            archive.read_member(b"first", None).unwrap().unwrap(),
            b"first".repeat(100)
        );
        assert_eq!(
            archive.read_member_at(1, None).unwrap().unwrap(),
            b"first".repeat(100)
        );
        assert_eq!(
            archive.read_member(b"last", None).unwrap_err().kind(),
            ErrorKind::PasswordRequired
        );
        assert_eq!(
            archive.read_member_at(3, None).unwrap_err().kind(),
            ErrorKind::PasswordRequired
        );
        assert_eq!(
            archive
                .read_member(b"last", Some(b"password"))
                .unwrap()
                .unwrap(),
            b"last".repeat(100)
        );
        assert!(archive.read_member(b"last", Some(b"wrong")).is_err());
    }
}

#[test]
fn selection_preserves_target_integrity_and_last_duplicate_name_identity() {
    for solid in [false, true] {
        let mut builder = Builder::new(ArchiveVersion::Rar29).solid(solid);
        builder
            .add_bytes(b"first".to_vec(), b"first payload".to_vec(), None, None)
            .unwrap();
        builder
            .add_bytes(b"second".to_vec(), b"second payload".to_vec(), None, None)
            .unwrap();
        let mut archive = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
        if let Archive::Rar15To40(legacy) = &mut archive {
            let mut files = legacy.blocks.iter_mut().filter_map(|block| match block {
                rars::rar15_40::Block::File(file) => Some(file),
                _ => None,
            });
            let first = files.next().unwrap();
            first.file_crc ^= 1;
            first.name = b"same".to_vec();
            files.next().unwrap().name = b"same".to_vec();
        }
        assert_eq!(
            archive.read_member_at(0, None).unwrap_err().kind(),
            ErrorKind::ChecksumMismatch
        );
        if solid {
            assert_eq!(
                archive.read_member(b"same", None).unwrap_err().kind(),
                ErrorKind::ChecksumMismatch
            );
        } else {
            assert_eq!(
                archive.read_member(b"same", None).unwrap().unwrap(),
                b"second payload"
            );
            assert_eq!(
                archive.read_member_at(1, None).unwrap().unwrap(),
                b"second payload"
            );
        }
        assert_eq!(
            archive.test(None).unwrap_err().kind(),
            ErrorKind::ChecksumMismatch
        );
    }
}

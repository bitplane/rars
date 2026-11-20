use super::support::scratch;
use rars::*;
use std::fs;

#[test]
fn builder_rejects_legacy_volume_directory_and_metadata_settings() {
    use rars::{ArchiveVersion, Builder, ErrorKind};

    let mut volume = Builder::new(ArchiveVersion::Rar29).volume_size(Some(64));
    assert_eq!(
        volume
            .add_directory(b"dir".to_vec(), None, None)
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidArgument
    );
    assert_eq!(
        Builder::new(ArchiveVersion::Rar29)
            .archive_metadata(None, false, false)
            .err()
            .unwrap()
            .kind(),
        ErrorKind::InvalidArgument
    );
}

#[test]
fn renaming_a_member_to_its_existing_name_preserves_its_identity() {
    use rars::{ArchiveReader, ArchiveVersion, Builder};

    let mut builder = Builder::new(ArchiveVersion::Rar50).store(true);
    builder
        .add_bytes(b"file".to_vec(), b"payload".to_vec(), None, None)
        .unwrap();
    let id = builder.entry_id(b"file").unwrap();
    builder.rename_by_id(id, b"file".to_vec()).unwrap();
    let archive = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
    assert_eq!(
        archive.read_member(b"file", None).unwrap().unwrap(),
        b"payload"
    );
}

#[test]
fn builder_rejects_unsupported_per_entry_password_shapes() {
    use rars::{ArchiveVersion, Builder, ErrorKind};

    for format in [
        ArchiveVersion::Rar13,
        ArchiveVersion::Rar29,
        ArchiveVersion::Rar50,
    ] {
        let mut builder = Builder::new(format).store(true);
        builder
            .add_bytes(b"file".to_vec(), b"payload".to_vec(), None, None)
            .unwrap();
        assert_eq!(
            builder
                .set_entry_encryption(b"file", Some(Vec::new()), None)
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidArgument
        );
        assert_eq!(
            builder
                .set_entry_encryption(b"file", None, Some(Vec::new()))
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidArgument
        );
        if format != ArchiveVersion::Rar50 {
            assert_eq!(
                builder
                    .set_entry_encryption(b"file", None, Some(b"comment".to_vec()))
                    .unwrap_err()
                    .kind(),
                ErrorKind::InvalidArgument
            );
        }
    }

    let mut volume = Builder::new(ArchiveVersion::Rar29)
        .store(true)
        .volume_size(Some(64));
    volume
        .add_bytes(b"file".to_vec(), b"payload".to_vec(), None, None)
        .unwrap();
    assert_eq!(
        volume
            .set_entry_encryption(b"file", Some(b"password".to_vec()), None)
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidArgument
    );
}

#[test]
#[cfg(feature = "encryption")]
fn rar13_entry_encryption_override_can_clear_the_builder_password() {
    use rars::{ArchiveReader, ArchiveVersion, Builder};

    for store in [false, true] {
        let mut builder = Builder::new(ArchiveVersion::Rar13)
            .store(store)
            .password(Some(b"default password".to_vec()));
        builder
            .add_bytes(b"plain".to_vec(), b"payload".to_vec(), None, None)
            .unwrap();
        builder.set_entry_encryption(b"plain", None, None).unwrap();
        let archive = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
        assert_eq!(
            archive.read_member(b"plain", None).unwrap().unwrap(),
            b"payload"
        );
    }
}

#[test]
fn legacy_builder_combines_inline_and_source_members() {
    use rars::{ArchiveReader, ArchiveVersion, Builder, EntrySource};

    let mut builder = Builder::new(ArchiveVersion::Rar29).store(true);
    builder
        .add_bytes(b"bytes".to_vec(), b"in memory".to_vec(), None, None)
        .unwrap();
    builder
        .add_source(
            b"source".to_vec(),
            EntrySource::from_bytes(b"from source".as_slice()),
            None,
            None,
        )
        .unwrap();
    let archive = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
    assert_eq!(
        archive.read_member(b"bytes", None).unwrap().unwrap(),
        b"in memory"
    );
    assert_eq!(
        archive.read_member(b"source", None).unwrap().unwrap(),
        b"from source"
    );
}

#[test]
fn directories_inside_a_solid_run_are_flagged_solid() {
    // 7-Zip restarts its decoder at any header without FHD_SOLID, so a
    // directory between two members of a run must carry it, or the member
    // after the directory cannot be read there.
    let text = b"shared text ".repeat(200);
    for target in [
        ArchiveVersion::Rar20,
        ArchiveVersion::Rar29,
        ArchiveVersion::Rar30,
        ArchiveVersion::Rar40,
    ] {
        let mut builder = Builder::new(target).solid(true);
        builder
            .add_directory(b"first".to_vec(), None, None)
            .unwrap();
        builder
            .add_bytes(b"first/a".to_vec(), text.clone(), None, None)
            .unwrap();
        builder
            .add_directory(b"second".to_vec(), None, None)
            .unwrap();
        builder
            .add_bytes(b"second/b".to_vec(), text.clone(), None, None)
            .unwrap();
        let archive = rars::ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
        let flags: Vec<_> = archive
            .as_rar15_40()
            .unwrap()
            .files()
            .map(|file| (file.is_directory(), file.is_solid()))
            .collect();
        // Nothing precedes the first directory or the first member; the
        // second directory and member continue the run.
        assert_eq!(
            flags,
            [(true, false), (false, false), (true, true), (false, true)],
            "{target:?}"
        );
        assert_eq!(
            archive.read_member(b"second/b", None).unwrap().unwrap(),
            text,
            "{target:?}"
        );
    }
}

#[test]
#[cfg(feature = "encryption")]
fn header_encryption_does_not_require_encrypted_members() {
    let mut builder = Builder::new(ArchiveVersion::Rar50)
        .password(Some(b"secret".to_vec()))
        .header_encryption(true);
    builder
        .add_bytes(b"plain".to_vec(), b"payload".to_vec(), None, None)
        .unwrap();
    builder.set_entry_encryption(b"plain", None, None).unwrap();
    let archive = rars::ArchiveReader::read_owned_with_options(
        builder.to_bytes().unwrap(),
        rars::ArchiveReadOptions::with_password(b"secret"),
    )
    .unwrap();
    let raw = archive.as_rar50().unwrap();
    assert!(raw.main.encrypted_headers);
    assert!(!raw.files().next().unwrap().encrypted);
    assert_eq!(
        archive.read_member(b"plain", None).unwrap().unwrap(),
        b"payload"
    );
    assert!(archive.rewrite_preservation_issues().is_empty());
}

#[cfg(unix)]
#[test]
fn add_path_preserves_non_utf8_child_names() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let root = scratch::case("builder-non-utf8-name");
    let raw_source = root.join(OsStr::from_bytes(b"bad-\xff"));
    let native_name = match fs::write(&raw_source, b"payload") {
        Ok(()) => b"bad-\xff".as_slice(),
        Err(error)
            if error.kind() == std::io::ErrorKind::InvalidInput
                || error.raw_os_error() == Some(libc::EILSEQ) =>
        {
            // Some Unix filesystems reject byte names. The builder must
            // report the missing/unrepresentable source, never queue a
            // substituted filename or silently claim it was archived.
            for format in ArchiveVersion::ALL {
                let mut builder = Builder::new(format);
                let error = builder.add_path(&raw_source, b"explicit").unwrap_err();
                assert_eq!(error.kind(), rars::ErrorKind::Io);
                assert!(builder.is_empty());
            }
            // Continue exercising collection and explicit naming in every
            // format with a name this filesystem can actually represent.
            let name = "valid-日本語".as_bytes();
            fs::write(root.join(OsStr::from_bytes(name)), b"payload").unwrap();
            name
        }
        Err(error) => panic!("raw filename probe failed unexpectedly: {error}"),
    };
    let source = root.join(OsStr::from_bytes(native_name));
    for format in ArchiveVersion::ALL {
        let mut builder = Builder::new(format);
        for unsafe_name in [b"../bad-\xff".as_slice(), b"/bad-\xff"] {
            assert!(builder.add_path(&source, unsafe_name).is_err());
            assert!(builder.is_empty());
        }
        builder.add_path(&root, b"root").unwrap();
        let native_archive_name = [b"root/".as_slice(), native_name].concat();
        let name = if format.family() == ArchiveFamily::Rar50Plus {
            rars::filename::encode_rar50(&native_archive_name).into_owned()
        } else {
            native_archive_name
        };
        let archive = rars::ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
        assert_eq!(
            archive.read_member(&name, None).unwrap().unwrap(),
            b"payload"
        );
        // The same native source can also have an explicit archive name.
        builder.add_path(&source, b"explicit").unwrap();
        assert_eq!(
            builder.names().collect::<Vec<_>>(),
            vec![name.as_slice(), &b"explicit"[..]]
        );
    }
}

#[test]
fn add_path_preserves_unicode_child_names_and_contents() {
    let root = scratch::case("builder-unicode-names");
    fs::create_dir(root.join("日本語")).unwrap();
    for name in ["日本語", "кириллица", "replacement-\u{fffd}"] {
        fs::write(root.join("日本語").join(name), name.as_bytes()).unwrap();
    }
    let mut builder = Builder::new(ArchiveVersion::Rar50).store(true);
    builder.add_path(&root, b"root").unwrap();
    let archive = rars::ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
    for name in ["日本語", "кириллица", "replacement-\u{fffd}"] {
        let member_name = format!("root/日本語/{name}");
        assert_eq!(
            archive
                .read_member(member_name.as_bytes(), None)
                .unwrap()
                .unwrap(),
            name.as_bytes()
        );
    }
}

fn builder_with(format: ArchiveVersion) -> Builder {
    let mut builder = Builder::new(format);
    builder
        .add_bytes(b"a.txt".to_vec(), b"hello world".repeat(64), None, None)
        .unwrap();
    builder
        .add_bytes(b"dir/b.txt".to_vec(), b"second member".to_vec(), None, None)
        .unwrap();
    builder
}

/// Every version this crate can write, which is all of them. The loop is
/// over `ArchiveVersion::ALL` so a tenth version is a failing test rather
/// than a gap.
#[test]
fn writes_every_family() {
    for format in ArchiveVersion::ALL {
        let archive = builder_with(format).to_bytes().unwrap();
        let read = rars::ArchiveReader::read_owned(archive).unwrap();
        let names: Vec<_> = read
            .members()
            .map(|member| member.meta.name_bytes().to_vec())
            .collect();
        assert_eq!(
            names,
            vec![b"a.txt".to_vec(), b"dir/b.txt".to_vec()],
            "{format}"
        );
    }
}

#[test]
fn stored_and_compressed_round_trip_to_the_same_bytes() {
    for store in [false, true] {
        let archive = builder_with(ArchiveVersion::Rar50)
            .store(store)
            .to_bytes()
            .unwrap();
        let read = rars::ArchiveReader::read_owned(archive).unwrap();
        let data = read.read_member(b"a.txt", None).unwrap().unwrap();
        assert_eq!(data, b"hello world".repeat(64));
    }
}

#[test]
fn rejects_a_duplicate_name() {
    let mut builder = Builder::new(ArchiveVersion::Rar50);
    builder
        .add_bytes(b"a".to_vec(), vec![], None, None)
        .unwrap();
    let error = builder
        .add_bytes(b"a".to_vec(), vec![], None, None)
        .unwrap_err();
    assert!(error.to_string().contains("duplicate archive entry name"));
    assert_eq!(builder.names().collect::<Vec<_>>(), vec![&b"a"[..]]);
}

#[test]
fn rejected_edits_preserve_a_usable_archive() {
    let mut builder = builder_with(ArchiveVersion::Rar50).store(true);
    let before = builder.to_bytes().unwrap();
    assert!(builder.rename(b"a.txt", b"dir/b.txt".to_vec()).is_err());
    assert_eq!(builder.to_bytes().unwrap(), before);
    assert!(builder
        .add_bytes(b"a.txt".to_vec(), b"replacement".to_vec(), None, None)
        .is_err());
    assert_eq!(builder.to_bytes().unwrap(), before);

    builder.rename(b"a.txt", b"a.txt".to_vec()).unwrap();
    assert_eq!(builder.to_bytes().unwrap(), before);
    builder.rename(b"a.txt", b"renamed.txt".to_vec()).unwrap();
    let archive = rars::ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
    assert_eq!(
        archive.read_member(b"renamed.txt", None).unwrap().unwrap(),
        b"hello world".repeat(64)
    );
}

#[test]
fn legacy_byte_identity_survives_edits_without_unicode_validation() {
    for format in ArchiveVersion::ALL {
        if format.family() == ArchiveFamily::Rar50Plus {
            continue;
        }
        let mut builder = Builder::new(format).store(true);
        builder
            .add_bytes(b"old-\xff".to_vec(), b"payload".to_vec(), None, None)
            .unwrap();
        builder.rename(b"old-\xff", b"new-\xfe".to_vec()).unwrap();
        let archive = rars::ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
        assert_eq!(
            archive.read_member(b"new-\xfe", None).unwrap().unwrap(),
            b"payload"
        );
        builder.remove(b"new-\xfe").unwrap();
        assert!(builder.is_empty());
    }
    let mut modern = Builder::new(ArchiveVersion::Rar50);
    assert!(modern
        .add_bytes(b"old-\xff".to_vec(), vec![], None, None)
        .is_err());
}

#[test]
fn rejects_an_escaping_name() {
    let mut builder = Builder::new(ArchiveVersion::Rar50);
    for name in [&b"../escape"[..], b"/absolute", b"C:\\drive"] {
        assert!(builder
            .add_bytes(name.to_vec(), vec![], None, None)
            .is_err());
    }
}

#[test]
fn renames_and_removes() {
    let mut builder = builder_with(ArchiveVersion::Rar50);
    builder.rename(b"a.txt", b"c.txt".to_vec()).unwrap();
    builder.remove(b"dir/b.txt").unwrap();
    assert_eq!(builder.names().collect::<Vec<_>>(), vec![&b"c.txt"[..]]);
    assert!(builder.remove(b"gone").is_err());
    assert!(builder.rename(b"gone", b"x".to_vec()).is_err());
}

#[test]
fn refuses_a_single_archive_when_a_volume_size_is_set() {
    let error = builder_with(ArchiveVersion::Rar50)
        .volume_size(Some(4096))
        .to_bytes()
        .unwrap_err();
    assert!(error.to_string().contains("build_volumes"));
}

#[test]
fn splits_into_volumes() {
    let mut builder = Builder::new(ArchiveVersion::Rar50);
    builder
        .add_bytes(b"big.bin".to_vec(), vec![7u8; 300_000], None, None)
        .unwrap();
    let volumes = builder
        .store(true)
        .volume_size(Some(64 * 1024))
        .build_volumes(None)
        .unwrap();
    assert!(volumes.len() > 1, "expected a split, got {}", volumes.len());
}

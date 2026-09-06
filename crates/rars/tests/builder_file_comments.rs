use rars::{Archive, ArchiveReader, ArchiveVersion, Builder, ErrorKind};

#[test]
fn comments_follow_renames_and_round_trip_through_supported_writers() {
    for version in [
        ArchiveVersion::Rar14,
        ArchiveVersion::Rar15,
        ArchiveVersion::Rar20,
        ArchiveVersion::Rar29,
        ArchiveVersion::Rar30,
        ArchiveVersion::Rar40,
        ArchiveVersion::Rar50,
        ArchiveVersion::Rar70,
    ] {
        for stored in [true, false] {
            let mut builder = Builder::new(version).store(stored);
            builder
                .add_bytes(b"first".to_vec(), b"payload".to_vec(), None, None)
                .unwrap();
            builder
                .add_bytes(b"second".to_vec(), vec![], None, None)
                .unwrap();
            builder
                .set_file_comment(b"first", Some(b"note\xff".to_vec()))
                .unwrap();
            builder.set_file_comment(b"second", Some(vec![])).unwrap();
            builder.rename(b"first", b"renamed".to_vec()).unwrap();
            let archive = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
            assert_eq!(
                archive.member_comments(None).unwrap(),
                vec![Some(b"note\xff".to_vec()), Some(vec![])],
                "{version:?}"
            );
            assert_eq!(
                archive.member_comment_at(0, None).unwrap(),
                Some(b"note\xff".to_vec())
            );
            assert_eq!(
                archive.read_member(b"renamed", None).unwrap().unwrap(),
                b"payload"
            );
            assert_eq!(
                archive.member_comment_at(2, None).unwrap_err().kind(),
                ErrorKind::EntryNotFound
            );
        }
    }
}

#[test]
fn encrypted_headers_reject_incompatible_embedded_comments() {
    for version in [ArchiveVersion::Rar30, ArchiveVersion::Rar40] {
        let mut builder = Builder::new(version)
            .password(Some(b"secret".to_vec()))
            .header_encryption(true);
        builder
            .add_bytes(b"file".to_vec(), b"payload".to_vec(), None, None)
            .unwrap();
        builder
            .set_file_comment(b"file", Some(b"note".to_vec()))
            .unwrap();
        assert!(matches!(
            builder.to_bytes(),
            Err(rars::Error::UnsupportedWriterOption {
                option: rars::write_plan::WriterOption::FileComment,
                ..
            })
        ));
        builder.set_file_comment(b"file", None).unwrap();
        let builder = builder.header_encryption(false).password(None);
        let archive = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
        assert_eq!(archive.member_comments(None).unwrap(), vec![None]);
        assert_eq!(
            archive.read_member(b"file", None).unwrap().unwrap(),
            b"payload"
        );
    }
}

#[test]
fn volume_output_refuses_comments_even_when_configured_after_the_comment() {
    for version in [
        ArchiveVersion::Rar14,
        ArchiveVersion::Rar29,
        ArchiveVersion::Rar50,
    ] {
        let mut builder = Builder::new(version).store(true);
        builder
            .add_bytes(b"file".to_vec(), b"payload".to_vec(), None, None)
            .unwrap();
        builder
            .set_file_comment(b"file", Some(b"note".to_vec()))
            .unwrap();
        let mut builder = builder.volume_size(Some(4096));
        assert!(matches!(
            builder.build_volumes(None),
            Err(rars::Error::UnsupportedWriterOption {
                option: rars::write_plan::WriterOption::FileComment,
                ..
            })
        ));
        assert!(builder.set_file_comment(b"file", Some(vec![])).is_err());
        builder.set_file_comment(b"file", None).unwrap();
        assert!(!builder.build_volumes(None).unwrap().is_empty());
    }
}

#[test]
fn rar5_file_comments_follow_output_encryption_and_can_be_removed() {
    let mut builder = Builder::new(ArchiveVersion::Rar50).password(Some(b"secret".to_vec()));
    builder
        .add_bytes(b"file".to_vec(), b"payload".to_vec(), None, None)
        .unwrap();
    builder
        .set_file_comment(b"file", Some(b"private note".to_vec()))
        .unwrap();
    let archive = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
    assert_eq!(
        archive.member_comment_at(0, None).unwrap_err().kind(),
        ErrorKind::PasswordRequired
    );
    assert_eq!(
        archive.member_comment_at(0, Some(b"secret")).unwrap(),
        Some(b"private note".to_vec())
    );
    builder.set_file_comment(b"file", Some(vec![])).unwrap();
    let archive = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
    assert_eq!(
        archive.member_comment_at(0, Some(b"secret")).unwrap(),
        Some(vec![])
    );
    builder.set_file_comment(b"file", None).unwrap();
    let archive = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
    assert_eq!(archive.member_comments(None).unwrap(), vec![None]);
}

#[test]
fn preflight_accepts_attached_comments_but_rejects_duplicates_and_read_checks_integrity() {
    let mut builder = Builder::new(ArchiveVersion::Rar50)
        .store(true)
        .comment(Some(b"archive".to_vec()));
    builder.add_directory(b"dir".to_vec(), None, None).unwrap();
    builder
        .set_file_comment(b"dir", Some(b"directory".to_vec()))
        .unwrap();
    builder
        .add_bytes(b"file".to_vec(), vec![], None, None)
        .unwrap();
    builder
        .set_file_comment(b"file", Some(b"file note".to_vec()))
        .unwrap();
    let mut archive = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
    assert!(archive.rewrite_preservation_issues().is_empty());
    assert_eq!(
        archive.member_comments(None).unwrap(),
        [Some(b"directory".to_vec()), Some(b"file note".to_vec())]
    );
    let Archive::Rar50Plus(a) = &mut archive else {
        unreachable!()
    };
    let at = a
        .blocks
        .iter()
        .rposition(|b| matches!(b, rars::rar50::Block::Service(_)))
        .unwrap();
    let original = a.blocks[at].clone();
    if let rars::rar50::Block::Service(file) = &mut a.blocks[at] {
        file.hash = None;
        file.data_crc32 = Some(0);
    }
    assert_eq!(
        archive.member_comment_at(1, None).unwrap_err().kind(),
        ErrorKind::ChecksumMismatch
    );
    let Archive::Rar50Plus(a) = &mut archive else {
        unreachable!()
    };
    a.blocks[at] = original.clone();
    a.blocks.insert(at, original);
    assert!(!archive.rewrite_preservation_issues().is_empty());
    assert!(archive.member_comments(None).is_err());
    assert!(archive.member_comment_at(1, None).is_err());
}

#[test]
fn legacy_archive_comment_encryption_is_independent_of_member_passwords() {
    for encrypted_headers in [false, true] {
        let password = b"secret";
        let mut builder = Builder::new(ArchiveVersion::Rar40)
            .password(Some(password.to_vec()))
            .header_encryption(encrypted_headers)
            .comment(Some(b"private comment".to_vec()))
            .archive_comment_password(Some(password.to_vec()));
        builder
            .add_bytes(b"plain".to_vec(), b"public".to_vec(), None, None)
            .unwrap();
        builder.set_entry_encryption(b"plain", None, None).unwrap();
        let source = ArchiveReader::read_owned_with_options(
            builder.to_bytes().unwrap(),
            rars::ArchiveReadOptions::with_password(password),
        )
        .unwrap();
        assert_eq!(
            source.comment(Some(password)).unwrap(),
            Some(b"private comment".to_vec())
        );
        assert!(!source.members().next().unwrap().meta.is_encrypted);
        assert!(source.rewrite_preservation_issues().is_empty());
        let mut editor = source
            .preserving_builder(Some(password))
            .unwrap()
            .comment(source.comment(Some(password)).unwrap());
        editor
            .add_bytes(b"renamed".to_vec(), b"public".to_vec(), None, None)
            .unwrap();
        editor.set_entry_encryption(b"renamed", None, None).unwrap();
        let output = ArchiveReader::read_owned_with_options(
            editor.to_bytes().unwrap(),
            rars::ArchiveReadOptions::with_password(password),
        )
        .unwrap();
        assert_eq!(
            output.comment(Some(password)).unwrap(),
            Some(b"private comment".to_vec())
        );
        assert!(output.comment(None).is_err());
        assert!(!output.members().next().unwrap().meta.is_encrypted);
        if let Archive::Rar15To40(archive) = output {
            assert_eq!(archive.main.has_encrypted_headers(), encrypted_headers);
            assert!(archive.new_subs().next().unwrap().file.is_encrypted());
        } else {
            panic!("legacy output expected");
        }
    }
}

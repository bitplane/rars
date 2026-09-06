use rars::{ArchiveReader, ArchiveVersion, Builder};

#[test]
fn unix_symlinks_round_trip_without_resolving_targets() {
    for format in [ArchiveVersion::Rar50, ArchiveVersion::Rar70] {
        for stored in [false, true] {
            let mut builder = Builder::new(format).store(stored);
            builder
                .add_unix_symlink(
                    b"link".to_vec(),
                    b"../missing".to_vec(),
                    false,
                    Some(123),
                    Some(0o750),
                )
                .unwrap();
            builder
                .set_file_comment(b"link", Some(b"note".to_vec()))
                .unwrap();
            builder
                .add_unix_symlink(
                    b"directory-link".to_vec(),
                    b"missing-dir".to_vec(),
                    true,
                    None,
                    None,
                )
                .unwrap();
            builder
                .add_bytes(b"file".to_vec(), b"payload".to_vec(), None, None)
                .unwrap();
            builder.rename(b"link", b"renamed".to_vec()).unwrap();
            let archive = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
            assert!(archive.rewrite_preservation_issues().is_empty());
            let members: Vec<_> = archive.members().collect();
            assert_eq!(
                members[0].unix_symlink().unwrap().target_name,
                b"../missing"
            );
            assert_eq!(members[0].meta.file_attr, 0o120750);
            assert_eq!(members[0].meta.file_time, Some(123));
            assert_eq!(members[1].unix_symlink().unwrap().flags, 1);
            assert!(!members[1].meta.is_directory);
            assert_eq!(archive.read_member_at(0, None).unwrap(), None);
            assert_eq!(
                archive.read_member_at(2, None).unwrap().unwrap(),
                b"payload"
            );
            assert_eq!(
                archive.member_comment_at(0, None).unwrap(),
                Some(b"note".to_vec())
            );
            assert_eq!(
                archive.read_member(b"file", None).unwrap().unwrap(),
                b"payload"
            );
        }
    }
}

#[test]
fn unsupported_link_options_leave_entries_unchanged() {
    let mut builder = Builder::new(ArchiveVersion::Rar50);
    for target in [b"".as_slice(), b"bad\0target", b"\xff"] {
        assert!(builder
            .add_unix_symlink(b"link".to_vec(), target.to_vec(), false, None, None)
            .is_err());
        assert!(builder.is_empty());
    }
    builder
        .add_unix_symlink(b"link".to_vec(), b"target".to_vec(), false, None, None)
        .unwrap();
    assert!(builder.set_dos_attributes(b"link", 0x20).is_err());
    assert!(builder.volume_size(Some(4096)).build_volumes(None).is_err());
    let mut legacy = Builder::new(ArchiveVersion::Rar29);
    assert!(legacy
        .add_unix_symlink(b"link".to_vec(), b"target".to_vec(), false, None, None)
        .is_err());
    assert!(legacy.is_empty());
}

#[test]
fn preflight_rejects_unsupported_redirections_and_inconsistent_link_headers() {
    let mut builder = Builder::new(ArchiveVersion::Rar50).store(true);
    builder
        .add_unix_symlink(b"link".to_vec(), b"target".to_vec(), false, None, None)
        .unwrap();
    let original = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
    for damage in 0..6 {
        let mut archive = original.clone();
        let rars::Archive::Rar50Plus(a) = &mut archive else {
            unreachable!()
        };
        let file = a
            .blocks
            .iter_mut()
            .find_map(|block| match block {
                rars::rar50::Block::File(file) => Some(file),
                _ => None,
            })
            .unwrap();
        match damage {
            0 => file.redirection.as_mut().unwrap().redirection_type = 4,
            1 => file.redirection.as_mut().unwrap().flags = 2,
            2 => file.host_os = 0,
            3 => file.attributes = 0o100644,
            4 => file.unpacked_size = 1,
            _ => file.file_flags |= 1,
        }
        assert!(archive.members().next().unwrap().unix_symlink().is_none());
        assert!(!archive.rewrite_preservation_issues().is_empty());
    }
}

#[test]
fn links_survive_solid_and_encrypted_output_and_unix_byte_mapping() {
    for solid in [false, true] {
        let mut builder = Builder::new(ArchiveVersion::Rar50)
            .solid(solid)
            .password(Some(b"secret".to_vec()));
        let target = rars::filename::encode_rar50(b"native-\xff").into_owned();
        builder
            .add_unix_symlink(b"link".to_vec(), target.clone(), false, None, None)
            .unwrap();
        builder
            .add_bytes(b"file".to_vec(), b"payload".repeat(100), None, None)
            .unwrap();
        let archive = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
        let member = archive.members().next().unwrap();
        assert_eq!(member.unix_symlink().unwrap().target_name, target);
        assert_eq!(member.meta.unpacked_size, 8);
        assert_eq!(
            archive.read_member_at(1, Some(b"secret")).unwrap().unwrap(),
            b"payload".repeat(100)
        );
    }
}

#[test]
fn retains_windows_links_and_file_copy_records() {
    let mut seed = Builder::new(ArchiveVersion::Rar50).store(true);
    seed.add_unix_symlink(b"link".to_vec(), b"target".to_vec(), false, None, None)
        .unwrap();
    let seed = ArchiveReader::read_owned(seed.to_bytes().unwrap())
        .unwrap()
        .members()
        .next()
        .unwrap();
    for kind in [2, 3, 4, 5] {
        let mut member = seed.clone();
        member.meta.host_os = Some(0);
        member.meta.is_directory = kind == 3;
        member.meta.file_attr = match kind {
            2 => 0x400,
            3 => 0x410,
            _ => 0x20,
        };
        member.meta.unpacked_size = if kind >= 4 { 7 } else { 0 };
        if let rars::ArchiveMemberDetail::Rar50Plus {
            redirection: Some(link),
            ..
        } = &mut member.detail
        {
            link.redirection_type = kind;
            link.flags = u64::from(kind == 3);
        }
        let mut builder = Builder::new(ArchiveVersion::Rar50).store(true);
        builder
            .add_bytes(b"target".to_vec(), b"payload".to_vec(), None, None)
            .unwrap();
        builder.add_archive_redirection(&member).unwrap();
        let output = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
        assert!(
            output.rewrite_preservation_issues().is_empty(),
            "{kind}: {:?}",
            output.rewrite_preservation_issues()
        );
        let actual = output.members().nth(1).unwrap();
        assert_eq!(
            actual.supported_redirection(),
            member.supported_redirection()
        );
        assert_eq!(actual.meta.unpacked_size, member.meta.unpacked_size);
        assert_eq!(actual.meta.file_attr, member.meta.file_attr);
        if kind >= 4 {
            builder.rename(b"target", b"renamed".to_vec()).unwrap();
            let output = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
            assert_eq!(
                output
                    .members()
                    .nth(1)
                    .unwrap()
                    .supported_redirection()
                    .unwrap()
                    .target_name,
                b"renamed"
            );
            builder.remove(b"renamed").unwrap();
            assert!(builder.to_bytes().is_err());
        }
    }
}

#[test]
fn legacy_link_payloads_are_decoded_with_integrity_and_password_checks() {
    for format in [ArchiveVersion::Rar29, ArchiveVersion::Rar40] {
        let mut builder = Builder::new(format).password(Some(b"secret".to_vec()));
        builder
            .add_bytes(
                b"link".to_vec(),
                b"missing-\xff".to_vec(),
                None,
                Some(0o120750),
            )
            .unwrap();
        builder
            .add_bytes(b"file".to_vec(), b"payload".to_vec(), None, Some(0o100644))
            .unwrap();
        let archive = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
        assert!(archive.legacy_symlink_target_at(0, None).is_err());
        assert_eq!(
            archive
                .legacy_symlink_target_at(0, Some(b"secret"))
                .unwrap(),
            Some(b"missing-\xff".to_vec())
        );
        assert_eq!(
            archive
                .legacy_symlink_target_at(1, Some(b"secret"))
                .unwrap(),
            None
        );
        assert!(archive
            .legacy_symlink_target_at(2, Some(b"secret"))
            .is_err());
    }
}

use rars::{ArchiveReader, ArchiveVersion, Builder, EntrySource};

#[test]
fn duplicate_payloads_and_metadata_follow_ids_in_every_family() {
    for format in [
        ArchiveVersion::Rar14,
        ArchiveVersion::Rar15,
        ArchiveVersion::Rar20,
        ArchiveVersion::Rar29,
        ArchiveVersion::Rar30,
        ArchiveVersion::Rar40,
        ArchiveVersion::Rar50,
        ArchiveVersion::Rar70,
    ] {
        let mut builder = Builder::new(format).store(true).allow_duplicate_names(true);
        builder
            .add_bytes(b"same".to_vec(), b"first".to_vec(), None, None)
            .unwrap();
        builder.add_directory(b"same".to_vec(), None, None).unwrap();
        builder
            .add_bytes(b"same".to_vec(), b"second".to_vec(), None, None)
            .unwrap();
        assert!(builder.remove(b"same").is_err());
        assert_eq!(builder.len(), 3);
        builder.rename_by_id(2, b"second".to_vec()).unwrap();
        builder.remove_by_id(1).unwrap();
        builder.rename_by_id(0, b"first".to_vec()).unwrap();
        assert_eq!(builder.member_ids().collect::<Vec<_>>(), [0, 2]);
        assert!(builder.remove_by_id(1).is_err());
        let bytes = builder.to_bytes().unwrap();
        let archive = ArchiveReader::read_owned(bytes).unwrap();
        let members: Vec<_> = archive.members().collect();
        assert_eq!(members[0].meta.name, b"first");
        assert_eq!(members[1].meta.name, b"second");
        assert_eq!(archive.read_member_at(0, None).unwrap().unwrap(), b"first");
        assert_eq!(archive.read_member_at(1, None).unwrap().unwrap(), b"second");
        assert_eq!(members[0].meta.unpacked_size, 5);
        assert_eq!(members[1].meta.unpacked_size, 6);
    }
}

#[test]
fn removing_a_duplicate_cannot_retarget_a_file_copy() {
    let mut seed = Builder::new(ArchiveVersion::Rar50).store(true);
    seed.add_unix_symlink(b"copy".to_vec(), b"same".to_vec(), false, None, None)
        .unwrap();
    let archive = ArchiveReader::read_owned(seed.to_bytes().unwrap()).unwrap();
    let mut copy = archive.members().next().unwrap();
    copy.meta.host_os = Some(0);
    copy.meta.file_attr = 0x20;
    copy.meta.unpacked_size = 7;
    if let rars::ArchiveMemberDetail::Rar50Plus {
        redirection: Some(link),
        ..
    } = &mut copy.detail
    {
        link.redirection_type = 5;
        link.flags = 0;
    }

    let mut builder = Builder::new(ArchiveVersion::Rar50)
        .store(true)
        .allow_duplicate_names(true);
    builder
        .add_source(
            b"same".to_vec(),
            EntrySource::from_bytes(b"payload".as_slice()),
            None,
            None,
        )
        .unwrap();
    builder.add_archive_redirection(&copy).unwrap();
    builder
        .add_bytes(b"same".to_vec(), b"another".to_vec(), None, None)
        .unwrap();
    assert!(matches!(
        builder.remove_by_id(0),
        Err(rars::Error::InvalidArgument(
            "removing this duplicate would retarget a hard link or file copy"
        ))
    ));
    assert_eq!(builder.member_ids().collect::<Vec<_>>(), [0, 1, 2]);
    builder.remove_by_id(2).unwrap();
    let output = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
    assert!(output.rewrite_preservation_issues().is_empty());
    assert_eq!(output.read_member_at(0, None).unwrap().unwrap(), b"payload");

    let mut shadowed = Builder::new(ArchiveVersion::Rar50)
        .store(true)
        .allow_duplicate_names(true);
    for data in [b"payload".as_slice(), b"another".as_slice()] {
        shadowed
            .add_bytes(b"same".to_vec(), data.to_vec(), None, None)
            .unwrap();
    }
    shadowed.add_archive_redirection(&copy).unwrap();
    shadowed.remove_by_id(0).unwrap();
    let output = ArchiveReader::read_owned(shadowed.to_bytes().unwrap()).unwrap();
    assert!(output.rewrite_preservation_issues().is_empty());
    assert_eq!(output.read_member_at(0, None).unwrap().unwrap(), b"another");
}

#[test]
fn removing_a_duplicate_ignores_directories_and_unrelated_copies() {
    let mut seed = Builder::new(ArchiveVersion::Rar50).store(true);
    seed.add_unix_symlink(b"copy".to_vec(), b"other".to_vec(), false, None, None)
        .unwrap();
    let archive = ArchiveReader::read_owned(seed.to_bytes().unwrap()).unwrap();
    let mut copy = archive.members().next().unwrap();
    copy.meta.host_os = Some(0);
    copy.meta.file_attr = 0x20;
    copy.meta.unpacked_size = 7;
    if let rars::ArchiveMemberDetail::Rar50Plus {
        redirection: Some(link),
        ..
    } = &mut copy.detail
    {
        link.redirection_type = 5;
        link.flags = 0;
    }

    let mut builder = Builder::new(ArchiveVersion::Rar50)
        .store(true)
        .allow_duplicate_names(true);
    builder
        .add_bytes(b"same".to_vec(), b"first".to_vec(), None, None)
        .unwrap();
    builder.add_directory(b"same".to_vec(), None, None).unwrap();
    builder
        .add_bytes(b"other".to_vec(), b"payload".to_vec(), None, None)
        .unwrap();
    builder.add_archive_redirection(&copy).unwrap();
    builder
        .add_bytes(b"same".to_vec(), b"second".to_vec(), None, None)
        .unwrap();

    builder.remove_by_id(0).unwrap();
    let output = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
    let copy = output.members().find(|member| member.meta.name == b"copy").unwrap();
    assert_eq!(copy.supported_redirection().unwrap().target_name, b"other");
    assert_eq!(output.read_member(b"other", None).unwrap().unwrap(), b"payload");
    assert_eq!(output.read_member(b"same", None).unwrap().unwrap(), b"second");
}

#[test]
fn renaming_a_duplicate_updates_only_copies_of_that_identity() {
    let mut seed = Builder::new(ArchiveVersion::Rar50).store(true);
    seed.add_unix_symlink(b"copy".to_vec(), b"same".to_vec(), false, None, None)
        .unwrap();
    let archive = ArchiveReader::read_owned(seed.to_bytes().unwrap()).unwrap();
    let mut copy = archive.members().next().unwrap();
    copy.meta.host_os = Some(0);
    copy.meta.file_attr = 0x20;
    copy.meta.unpacked_size = 7;
    if let rars::ArchiveMemberDetail::Rar50Plus {
        redirection: Some(link),
        ..
    } = &mut copy.detail
    {
        link.redirection_type = 5;
        link.flags = 0;
    }

    let mut builder = Builder::new(ArchiveVersion::Rar50)
        .store(true)
        .allow_duplicate_names(true);
    builder
        .add_bytes(b"same".to_vec(), b"payload".to_vec(), None, None)
        .unwrap();
    builder.add_archive_redirection(&copy).unwrap();
    builder
        .add_bytes(b"same".to_vec(), b"another".to_vec(), None, None)
        .unwrap();
    copy.meta.name = b"later-copy".to_vec();
    builder.add_archive_redirection(&copy).unwrap();
    builder
        .add_bytes(b"other".to_vec(), b"payload".to_vec(), None, None)
        .unwrap();
    copy.meta.name = b"other-copy".to_vec();
    if let rars::ArchiveMemberDetail::Rar50Plus {
        redirection: Some(link),
        ..
    } = &mut copy.detail
    {
        link.target_name = b"other".to_vec();
    }
    builder.add_archive_redirection(&copy).unwrap();

    builder.rename_by_id(0, b"first".to_vec()).unwrap();
    let output = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
    for (name, target) in [
        (b"copy".as_slice(), b"first".as_slice()),
        (b"later-copy".as_slice(), b"same".as_slice()),
        (b"other-copy".as_slice(), b"other".as_slice()),
    ] {
        let member = output.members().find(|member| member.meta.name == name).unwrap();
        assert_eq!(member.supported_redirection().unwrap().target_name, target);
    }
}

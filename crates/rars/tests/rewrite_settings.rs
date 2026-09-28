use rars::{ArchiveReader, ArchiveVersion, Builder};

#[test]
fn preserving_builder_accepts_rar13_family_and_rar7_sources() {
    for version in [
        ArchiveVersion::Rar13,
        ArchiveVersion::Rar14,
        ArchiveVersion::Rar70,
    ] {
        let mut builder = Builder::new(version).store(false);
        builder
            .add_bytes(
                b"source".to_vec(),
                b"payload payload payload".repeat(8),
                None,
                None,
            )
            .unwrap();
        let source = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
        assert!(
            source.rewrite_preservation_issues().is_empty(),
            "{version:?}: {:?}",
            source.rewrite_preservation_issues()
        );
        let mut preserving = source.preserving_builder(None).unwrap();
        preserving
            .add_bytes(
                b"source".to_vec(),
                b"payload payload payload".repeat(8),
                None,
                None,
            )
            .unwrap();
        preserving
            .add_bytes(b"added".to_vec(), b"new payload".to_vec(), None, None)
            .unwrap();
        let output = ArchiveReader::read_owned(preserving.to_bytes().unwrap()).unwrap();
        assert!(output.rewrite_preservation_issues().is_empty());
        assert_eq!(
            output.read_member_at(0, None).unwrap().unwrap(),
            b"payload payload payload".repeat(8)
        );
        assert_eq!(
            output.read_member_at(1, None).unwrap().unwrap(),
            b"new payload"
        );
    }
}

#[test]
fn preserving_builder_requires_password_for_encrypted_rar14_members() {
    let mut builder = Builder::new(ArchiveVersion::Rar14)
        .store(true)
        .password(Some(b"secret".to_vec()));
    builder
        .add_bytes(b"encrypted".to_vec(), b"payload".to_vec(), None, None)
        .unwrap();
    let source = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
    assert!(source.rewrite_preservation_issues().is_empty());
    assert!(matches!(
        source.preserving_builder(None),
        Err(rars::Error::NeedPassword)
    ));
    assert!(matches!(
        source.preserving_builder(Some(b"")),
        Err(rars::Error::NeedPassword)
    ));
    let mut preserving = source.preserving_builder(Some(b"secret")).unwrap();
    preserving
        .add_bytes(b"encrypted".to_vec(), b"payload".to_vec(), None, None)
        .unwrap();
    let output = ArchiveReader::read_owned(preserving.to_bytes().unwrap()).unwrap();
    assert_eq!(
        output.read_member_at(0, Some(b"secret")).unwrap().unwrap(),
        b"payload"
    );
}

#[test]
fn preserving_builder_refuses_an_sfx_prefix_it_cannot_preserve() {
    let mut builder = Builder::new(ArchiveVersion::Rar50).store(true);
    builder
        .add_bytes(b"file".to_vec(), b"payload".to_vec(), None, None)
        .unwrap();
    let mut prefixed = b"MZ-stub".to_vec();
    prefixed.extend(builder.to_bytes().unwrap());
    let source = ArchiveReader::read_owned(prefixed).unwrap();
    assert!(source
        .rewrite_preservation_issues()
        .contains(&"SFX executable prefix".to_string()));
    assert!(matches!(
        source.preserving_builder(None),
        Err(rars::Error::InvalidArgument(
            "archive has unsupported preservation settings"
        ))
    ));
}

#[test]
fn mixed_data_and_comment_encryption_are_independent() {
    for solid in [false, true] {
        let mut builder = Builder::new(ArchiveVersion::Rar50)
            .solid(solid)
            .password(Some(b"secret".to_vec()));
        for name in [b"plain".as_slice(), b"encrypted"] {
            builder
                .add_bytes(name.to_vec(), b"payload".repeat(100), None, None)
                .unwrap();
            builder
                .set_file_comment(name, Some(b"comment".to_vec()))
                .unwrap();
        }
        builder
            .set_entry_encryption(b"plain", None, Some(b"secret".to_vec()))
            .unwrap();
        builder
            .set_entry_encryption(b"encrypted", Some(b"secret".to_vec()), None)
            .unwrap();
        let archive = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
        let members: Vec<_> = archive.members().collect();
        assert!(!members[0].meta.is_encrypted);
        assert!(members[1].meta.is_encrypted);
        assert_eq!(archive.member_comment_encryption(), [true, false]);
        assert!(archive.rewrite_preservation_issues().is_empty());
        assert!(archive.preserving_builder(None).is_err());
        assert!(archive.preserving_builder(Some(b"secret")).is_ok());
        assert_eq!(
            archive.read_member_at(1, Some(b"secret")).unwrap().unwrap(),
            b"payload".repeat(100)
        );
        assert_eq!(
            archive.member_comments(Some(b"secret")).unwrap(),
            [Some(b"comment".to_vec()), Some(b"comment".to_vec())]
        );
    }
}

#[test]
fn metadata_lock_indexes_and_recovery_are_retained_and_regenerated() {
    use rars::rar50::{
        ArchiveEntry, ArchiveMetadataEntry, MainExtraRecord, Rar50Writer, WriterOptions,
    };
    let bytes = Rar50Writer::new(WriterOptions::new(
        ArchiveVersion::Rar50,
        rars::FeatureSet::store_only(),
    ))
    .entries([ArchiveEntry::new(
        b"file".to_vec(),
        rars::EntrySource::from_bytes(b"payload".as_slice()),
    )
    .with_attributes(0x20)])
    .archive_metadata(Some(ArchiveMetadataEntry {
        name: Some(b"original.rar"),
        creation_time: Some(123),
    }))
    .finish()
    .unwrap();
    let seed = ArchiveReader::read_owned(bytes).unwrap();
    let rars::Archive::Rar50Plus(seed) = seed else {
        unreachable!()
    };
    let metadata = seed
        .main
        .extras
        .into_iter()
        .find_map(|extra| match extra {
            MainExtraRecord::ArchiveMetadata(value) => Some(value),
            _ => None,
        })
        .unwrap();
    for flags in [3, 7, 15] {
        let mut metadata = metadata.clone();
        metadata.flags = flags;
        let mut builder = Builder::new(ArchiveVersion::Rar50)
            .store(true)
            .recovery_percent(Some(5))
            .archive_metadata(Some(metadata.clone()), true, true)
            .unwrap();
        builder
            .add_bytes(b"file".to_vec(), b"payload".to_vec(), None, None)
            .unwrap();
        let source = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
        assert!(
            source.rewrite_preservation_issues().is_empty(),
            "{:?}",
            source.rewrite_preservation_issues()
        );
        let mut rewritten = source.preserving_builder(None).unwrap();
        rewritten
            .add_bytes(b"renamed".to_vec(), b"new payload".to_vec(), None, None)
            .unwrap();
        let output = ArchiveReader::read_owned(rewritten.to_bytes().unwrap()).unwrap();
        assert!(
            output.rewrite_preservation_issues().is_empty(),
            "{:?}",
            output.rewrite_preservation_issues()
        );
        let rars::Archive::Rar50Plus(output) = output else {
            unreachable!()
        };
        assert!(output.main.is_locked());
        assert!(output.main.has_recovery_record());
        assert!(output.main.extras.iter().any(
            |extra| matches!(extra, MainExtraRecord::ArchiveMetadata(value) if value == &metadata)
        ));
        assert!(output.blocks.iter().any(
            |block| matches!(block, rars::rar50::Block::Service(service) if service.name == b"QO")
        ));
    }
}

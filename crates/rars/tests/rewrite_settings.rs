use rars::{ArchiveReader, ArchiveVersion, Builder};

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

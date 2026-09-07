use rars::{ArchiveReader, ArchiveVersion, Builder};

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

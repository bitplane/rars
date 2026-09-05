use rars::{ArchiveReader, ArchiveVersion, Builder};

#[path = "support/scratch.rs"]
mod scratch;

#[test]
fn explicit_directories_survive_all_rar5_writer_paths() {
    let root = scratch::case("builder-directories");
    for format in [ArchiveVersion::Rar50, ArchiveVersion::Rar70] {
        for solid in [false, true] {
            let mut builder = Builder::new(format).solid(solid);
            builder
                .add_directory(b"empty".to_vec(), Some(123), None)
                .unwrap();
            builder
                .add_directory(b"nested".to_vec(), Some(456), Some(0o750))
                .unwrap();
            builder
                .set_mtime_nanoseconds(b"nested", 704_088_300)
                .unwrap();
            builder
                .add_bytes(b"nested/file".to_vec(), b"payload".repeat(20), None, None)
                .unwrap();
            let path = root.join(format!("{format}-{solid}.rar"));
            builder.write_to_path(&path, None).unwrap();
            let mut outputs = vec![builder.to_bytes().unwrap(), std::fs::read(path).unwrap()];
            outputs.extend(builder.volume_size(Some(4096)).build_volumes(None).unwrap());
            for bytes in outputs {
                let archive = ArchiveReader::read_owned(bytes).unwrap();
                let members: Vec<_> = archive.members().collect();
                assert_eq!(members.len(), 3);
                assert!(members[0].meta.is_directory);
                assert_eq!(members[0].meta.file_attr, 0x10);
                assert_eq!(members[0].meta.file_time, Some(123));
                assert!(members[1].meta.is_directory);
                assert_eq!(members[1].meta.file_attr, 0o040750);
                assert_eq!(
                    members[1].meta.mtime_refinement.unwrap().nanoseconds,
                    704_088_300
                );
                assert!(!members[2].meta.is_directory);
                assert_eq!(
                    archive.read_member(b"nested/file", None).unwrap().unwrap(),
                    b"payload".repeat(20)
                );
            }
        }
    }
}

#[test]
fn directory_validation_does_not_change_entry_kind_or_queued_names() {
    let mut builder = Builder::new(ArchiveVersion::Rar50).store(true);
    builder
        .add_directory(b"empty".to_vec(), None, None)
        .unwrap();
    let before = builder.to_bytes().unwrap();
    assert!(builder.set_dos_attributes(b"empty", 0x20).is_err());
    assert!(builder
        .add_directory(b"empty".to_vec(), None, None)
        .is_err());
    assert_eq!(builder.to_bytes().unwrap(), before);
    let mut legacy = Builder::new(ArchiveVersion::Rar29);
    assert!(legacy.add_directory(b"empty".to_vec(), None, None).is_err());
    assert!(legacy.is_empty());
}

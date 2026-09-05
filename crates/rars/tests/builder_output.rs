#[path = "support/scratch.rs"]
mod scratch;

use rars::{ArchiveReader, ArchiveVersion, Builder, EntrySource};
use std::fs;

#[test]
fn failed_builder_writes_preserve_the_destination_and_remove_staging_files() {
    for existing in [false, true] {
        let root = scratch::case("builder-failed-write");
        let destination = root.join("archive.rar");
        if existing {
            fs::write(&destination, b"previous archive").unwrap();
        }
        let mut builder = Builder::new(ArchiveVersion::Rar50).store(true);
        builder
            .add_source(
                b"file".to_vec(),
                EntrySource::from_opener(10, || {
                    Err(std::io::Error::other("injected source failure").into())
                }),
                None,
                None,
            )
            .unwrap();
        assert!(builder.write_to_path(&destination, None).is_err());
        if existing {
            assert_eq!(fs::read(&destination).unwrap(), b"previous archive");
        } else {
            assert!(!destination.exists());
        }
        assert_eq!(fs::read_dir(&root).unwrap().count(), usize::from(existing));
    }
}

#[test]
fn builder_publishes_successful_writes_and_cleans_up_failed_renames() {
    let root = scratch::case("builder-publish");
    let destination = root.join("archive.rar");
    let mut builder = Builder::new(ArchiveVersion::Rar50).store(true);
    builder
        .add_bytes(b"file".to_vec(), b"payload".to_vec(), None, None)
        .unwrap();
    fs::write(&destination, b"previous archive").unwrap();
    builder.write_to_path(&destination, None).unwrap();
    let archive = ArchiveReader::read_owned(fs::read(&destination).unwrap()).unwrap();
    assert_eq!(
        archive.read_member(b"file", None).unwrap().unwrap(),
        b"payload"
    );
    assert_eq!(fs::read_dir(&root).unwrap().count(), 1);

    fs::remove_file(&destination).unwrap();
    fs::create_dir(&destination).unwrap();
    assert!(builder.write_to_path(&destination, None).is_err());
    assert!(destination.is_dir());
    assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
}

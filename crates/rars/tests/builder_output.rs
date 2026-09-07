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

#[test]
fn legacy_recovery_requests_fail_before_reading_sources_or_writing_output() {
    for version in [
        ArchiveVersion::Rar13,
        ArchiveVersion::Rar14,
        ArchiveVersion::Rar15,
        ArchiveVersion::Rar20,
        ArchiveVersion::Rar29,
        ArchiveVersion::Rar30,
        ArchiveVersion::Rar40,
    ] {
        for percent in [0, 10] {
            let mut builder = Builder::new(version).recovery_percent(Some(percent));
            builder
                .add_source(
                    b"file".to_vec(),
                    EntrySource::from_opener(7, || {
                        panic!("unsupported recovery request must be rejected before opening input")
                    }),
                    None,
                    None,
                )
                .unwrap();
            assert_eq!(
                builder.to_bytes().unwrap_err().kind(),
                rars::ErrorKind::UnsupportedFeature
            );
            let mut output = Vec::new();
            assert_eq!(
                builder
                    .write_to(&mut output, &rars::WriterResources::default(), None)
                    .unwrap_err()
                    .kind(),
                rars::ErrorKind::UnsupportedFeature
            );
            assert!(output.is_empty());
            assert_eq!(
                builder
                    .volume_size(Some(1024))
                    .build_volumes(None)
                    .unwrap_err()
                    .kind(),
                rars::ErrorKind::UnsupportedFeature
            );
        }
    }
}

#[path = "support/scratch.rs"]
mod scratch;

use rars::{entry_relative_path, ArchiveReader, ArchiveVersion, Builder, EntrySource};
use std::fs;

#[test]
fn legacy_entry_paths_keep_relative_components_and_reject_escape() {
    assert_eq!(
        entry_relative_path(b"folder\\subdir/file.txt").unwrap(),
        std::path::Path::new("folder/subdir/file.txt")
    );
    assert_eq!(
        entry_relative_path(b"./file.txt").unwrap(),
        std::path::Path::new("file.txt")
    );
    for name in [
        b"../escape".as_slice(),
        b"/absolute",
        b"folder/../../escape",
        b"",
        b".",
    ] {
        assert!(entry_relative_path(name).is_err(), "{name:?}");
    }
}

#[cfg(unix)]
#[test]
fn legacy_entry_paths_preserve_non_utf8_bytes_on_unix() {
    use std::os::unix::ffi::OsStrExt;

    let path = entry_relative_path(b"folder/\xff.bin").unwrap();
    assert_eq!(path.as_os_str().as_bytes(), b"folder/\xff.bin");
}

#[test]
fn resource_aware_byte_output_matches_the_standard_builder_path() {
    for version in [ArchiveVersion::Rar29, ArchiveVersion::Rar50] {
        let mut builder = Builder::new(version).store(true);
        builder
            .add_bytes(b"file".to_vec(), b"payload".to_vec(), None, None)
            .unwrap();
        let expected = builder.to_bytes().unwrap();
        let actual = builder
            .to_bytes_with_resources(&rars::WriterResources::default(), None)
            .unwrap();
        assert_eq!(actual, expected, "{version:?}");
        let archive = ArchiveReader::read_owned(actual).unwrap();
        assert_eq!(archive.read_member(b"file", None).unwrap().unwrap(), b"payload");
    }
}

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

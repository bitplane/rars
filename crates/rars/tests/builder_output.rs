#[path = "support/scratch.rs"]
mod scratch;

use rars::{entry_relative_path, ArchiveReader, ArchiveVersion, Builder, EntrySource};
use std::fs;

#[test]
fn empty_rar50_builder_writes_a_readable_archive() {
    let archive =
        ArchiveReader::read_owned(Builder::new(ArchiveVersion::Rar50).to_bytes().unwrap()).unwrap();
    assert_eq!(archive.members().count(), 0);
}

#[test]
fn empty_legacy_builder_refuses_single_archive_output() {
    assert_eq!(
        Builder::new(ArchiveVersion::Rar29).to_bytes().unwrap_err(),
        rars::Error::InvalidArgument("archive builder has no entries")
    );
}

#[test]
fn legacy_volume_builder_refuses_existing_directories_and_symlinks() {
    let mut directory = Builder::new(ArchiveVersion::Rar29);
    directory.add_directory(b"dir".to_vec(), None, None).unwrap();
    assert_eq!(
        directory.volume_size(Some(64)).build_volumes(None).unwrap_err(),
        rars::Error::InvalidArgument(
            "legacy directories and symbolic links are unsupported in volume output"
        )
    );

    let mut symlink = Builder::new(ArchiveVersion::Rar29);
    symlink
        .add_unix_symlink(b"link".to_vec(), b"target".to_vec(), false, None, None)
        .unwrap();
    assert_eq!(
        symlink.volume_size(Some(64)).build_volumes(None).unwrap_err(),
        rars::Error::InvalidArgument(
            "legacy directories and symbolic links are unsupported in volume output"
        )
    );
}

#[test]
fn legacy_volumes_accept_regular_unix_mode_files() {
    for version in [ArchiveVersion::Rar20, ArchiveVersion::Rar29, ArchiveVersion::Rar40] {
        let mut builder = Builder::new(version).store(true).volume_size(Some(64));
        builder
            .add_bytes(b"file".to_vec(), vec![42; 128], None, Some(0o100640))
            .unwrap();
        let volumes = builder.build_volumes(None).unwrap();
        assert!(volumes.len() > 1, "{version:?}");
        let first = ArchiveReader::read_owned(volumes[0].clone()).unwrap();
        let member = first.members().next().unwrap();
        assert_eq!(member.meta.attr_source(), rars::AttrSource::Unix);
        assert_eq!(member.meta.file_attr & 0o170777, 0o100640);
    }
}

#[test]
fn single_output_rejects_volume_metadata_before_opening_a_source() {
    let mut builder = Builder::new(ArchiveVersion::Rar50)
        .archive_metadata(None, true, false)
        .unwrap()
        .volume_size(Some(64));
    builder
        .add_source(
            b"file".to_vec(),
            EntrySource::from_opener(1, || panic!("single-output refusal opened source")),
            None,
            None,
        )
        .unwrap();
    assert_eq!(
        builder.to_bytes().unwrap_err(),
        rars::Error::InvalidArgument(
            "archive metadata settings require the RAR5/7 streaming writer"
        )
    );
}

#[test]
fn path_output_reports_missing_parent_without_creating_an_archive() {
    let root = scratch::case("builder-missing-parent");
    let destination = root.join("missing").join("archive.rar");
    let mut builder = Builder::new(ArchiveVersion::Rar50).store(true);
    builder
        .add_bytes(b"file".to_vec(), b"payload".to_vec(), None, None)
        .unwrap();
    assert_eq!(
        builder.write_to_path(&destination, None).unwrap_err().kind(),
        rars::ErrorKind::Io
    );
    assert!(!destination.exists());
    assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
}

#[test]
fn volume_builder_refuses_quick_open_before_source_io() {
    let source = || EntrySource::from_opener(1, || panic!("volume setting opened source"));
    let mut builder = Builder::new(ArchiveVersion::Rar50)
        .archive_metadata(None, false, true)
        .unwrap()
        .volume_size(Some(64));
    builder
        .add_source(b"file".to_vec(), source(), None, None)
        .unwrap();
    assert_eq!(
        builder.build_volumes(None).unwrap_err(),
        rars::Error::InvalidArgument(
            "archive metadata settings are not supported in volume output"
        )
    );
}

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
fn header_encryption_uses_a_shared_entry_password_without_a_builder_default() {
    let mut builder = Builder::new(ArchiveVersion::Rar50)
        .store(true)
        .header_encryption(true);
    builder
        .add_bytes(b"file".to_vec(), b"payload".to_vec(), None, None)
        .unwrap();
    builder
        .set_entry_encryption(b"file", Some(b"secret".to_vec()), None)
        .unwrap();
    let archive = ArchiveReader::read_owned_with_options(
        builder.to_bytes().unwrap(),
        rars::ArchiveReadOptions::with_password(b"secret"),
    )
    .unwrap();
    assert_eq!(
        archive.read_member(b"file", Some(b"secret")).unwrap().unwrap(),
        b"payload"
    );
}

#[test]
fn missing_header_password_fails_before_reading_a_source() {
    let mut builder = Builder::new(ArchiveVersion::Rar50)
        .store(true)
        .header_encryption(true);
    builder
        .add_source(
            b"file".to_vec(),
            EntrySource::from_opener(7, || panic!("password error must precede source I/O")),
            None,
            None,
        )
        .unwrap();
    assert_eq!(builder.to_bytes().unwrap_err(), rars::Error::NeedPassword);
    let mut output = Vec::new();
    assert_eq!(
        builder
            .write_to(&mut output, &rars::WriterResources::default(), None)
            .unwrap_err(),
        rars::Error::NeedPassword
    );
    assert!(output.is_empty());
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

#[test]
fn volume_builder_rejects_unsupported_settings_before_opening_sources() {
    let source = || {
        EntrySource::from_opener(7, || {
            panic!("volume preflight must not open the member source")
        })
    };

    let mut commented = Builder::new(ArchiveVersion::Rar50)
        .comment(Some(b"comment".to_vec()))
        .volume_size(Some(1024));
    commented
        .add_source(b"file".to_vec(), source(), None, None)
        .unwrap();
    assert!(matches!(
        commented.build_volumes(None),
        Err(rars::Error::InvalidArgument("RAR 5 volume comments are not supported"))
    ));

    let mut locked = Builder::new(ArchiveVersion::Rar50)
        .archive_metadata(None, true, false)
        .unwrap()
        .volume_size(Some(1024));
    locked
        .add_source(b"file".to_vec(), source(), None, None)
        .unwrap();
    assert!(matches!(
        locked.build_volumes(None),
        Err(rars::Error::InvalidArgument(
            "archive metadata settings are not supported in volume output"
        ))
    ));

    let mut directory = Builder::new(ArchiveVersion::Rar20);
    directory
        .add_directory(b"directory".to_vec(), None, None)
        .unwrap();
    directory
        .add_source(b"file".to_vec(), source(), None, None)
        .unwrap();
    assert!(matches!(
        directory.volume_size(Some(1024)).build_volumes(None),
        Err(rars::Error::InvalidArgument(
            "legacy directories and symbolic links are unsupported in volume output"
        ))
    ));

    let empty = Builder::new(ArchiveVersion::Rar20).volume_size(Some(1024));
    assert!(matches!(
        empty.build_volumes(None),
        Err(rars::Error::InvalidArgument("archive builder has no entries"))
    ));

    let mut multiple = Builder::new(ArchiveVersion::Rar20)
        .store(true)
        .volume_size(Some(1024));
    for name in [b"first".as_slice(), b"second".as_slice()] {
        multiple
            .add_bytes(name.to_vec(), b"payload".to_vec(), None, None)
            .unwrap();
    }
    assert!(matches!(
        multiple.build_volumes(None),
        Err(rars::Error::InvalidArgument(
            "legacy volumes support one input"
        ))
    ));
}

#[test]
fn legacy_builder_rejects_modern_streaming_outputs_before_creating_files() {
    let mut builder = Builder::new(ArchiveVersion::Rar20).store(true);
    builder
        .add_source(
            b"file".to_vec(),
            EntrySource::from_opener(7, || {
                panic!("unsupported output must not open the source")
            }),
            None,
            None,
        )
        .unwrap();
    let resources = rars::WriterResources::default();
    assert!(matches!(
        builder.to_volume_output(&resources, None),
        Err(rars::Error::UnsupportedFamilyFeature {
            feature: "streaming managed volume output",
            ..
        })
    ));
    let mut sink = rars::rar50::CollectedVolumes::new();
    assert!(matches!(
        builder.write_volumes_to(&mut sink, &resources, None),
        Err(rars::Error::UnsupportedFamilyFeature {
            feature: "streaming managed volume output",
            ..
        })
    ));
    assert!(sink.take().is_empty());

    let root = scratch::case("builder-legacy-memory-quota");
    let destination = root.join("archive.rar");
    let limited = resources.with_max_memory_bytes(1024);
    assert!(matches!(
        builder.write_to_path_with_resources(&destination, &limited, None),
        Err(rars::Error::UnsupportedFamilyFeature {
            feature: "aggregate managed memory quota",
            ..
        })
    ));
    assert!(!destination.exists());
}

#[test]
fn legacy_builder_materializes_reopenable_sources_once() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    let payload = b"legacy source materialization ".repeat(32);
    for version in [ArchiveVersion::Rar13, ArchiveVersion::Rar20, ArchiveVersion::Rar29] {
        let opens = Arc::new(AtomicUsize::new(0));
        let opened = opens.clone();
        let data = payload.clone();
        let mut builder = Builder::new(version).store(false);
        builder
            .add_source(
                b"source".to_vec(),
                EntrySource::from_opener(payload.len() as u64, move || {
                    opened.fetch_add(1, Ordering::SeqCst);
                    Ok(Box::new(std::io::Cursor::new(data.clone())))
                }),
                None,
                None,
            )
            .unwrap();
        let archive = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
        assert_eq!(archive.read_member(b"source", None).unwrap().unwrap(), payload);
        assert_eq!(opens.load(Ordering::SeqCst), 1, "{version:?}");
    }
}

#[cfg(unix)]
#[test]
fn add_path_refuses_symlinks_without_following_them() {
    use std::os::unix::fs::symlink;

    let root = scratch::case("builder-input-symlink");
    let target = root.join("target");
    let link = root.join("link");
    fs::write(&target, b"private payload").unwrap();
    symlink(&target, &link).unwrap();
    let mut builder = Builder::new(ArchiveVersion::Rar50);
    let error = builder.add_path(&link, b"member").unwrap_err();
    assert_eq!(error.entry_context(), Some((&b"member"[..], "adding")));
    assert_eq!(error.kind(), rars::ErrorKind::InvalidArgument);
    assert!(builder.is_empty());
}

#[cfg(unix)]
#[test]
fn add_path_refuses_special_files_instead_of_silently_omitting_them() {
    let mut builder = Builder::new(ArchiveVersion::Rar50);
    let error = builder
        .add_path(std::path::Path::new("/dev/null"), b"member")
        .unwrap_err();
    assert_eq!(error.entry_context(), Some((&b"member"[..], "adding")));
    assert_eq!(error.kind(), rars::ErrorKind::InvalidArgument);
    assert!(builder.is_empty());
}

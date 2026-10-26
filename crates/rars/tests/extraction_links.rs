#![cfg(feature = "write")]
use rars::{Archive, ArchiveReadOptions, ArchiveReader, ArchiveVersion, Builder, ExtractedLink};
use std::{
    cell::RefCell,
    io::{self, Write},
    rc::Rc,
};

struct Capture(Rc<RefCell<Vec<u8>>>);
impl Write for Capture {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.0.borrow_mut().extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn fixture(version: ArchiveVersion, store: bool, solid: bool) -> Archive {
    let mut builder = Builder::new(version).store(store).solid(solid);
    builder
        .add_bytes(b"before".to_vec(), b"hello ".repeat(50), None, None)
        .unwrap();
    builder
        .add_unix_symlink(b"link".to_vec(), b"before".to_vec(), false, None, None)
        .unwrap();
    builder
        .add_bytes(b"after".to_vec(), b"hello ".repeat(50), None, None)
        .unwrap();
    ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap()
}
fn raw_link(target: &[u8], split: bool) -> Vec<Archive> {
    use rars::rar15_40::{write_stored_archive, write_stored_volumes, StoredEntry, WriterOptions};
    let entry = StoredEntry {
        name: b"link",
        data: target,
        file_time: 0,
        file_attr: 0o120777,
        host_os: 3,
        password: None,
        file_comment: None,
    };
    let parts = if split {
        write_stored_volumes(
            entry,
            WriterOptions::new(ArchiveVersion::Rar40, rars::FeatureSet::store_only()),
            128,
        )
        .unwrap()
    } else {
        vec![write_stored_archive(
            &[entry],
            WriterOptions::new(ArchiveVersion::Rar40, rars::FeatureSet::store_only()),
        )
        .unwrap()]
    };
    parts
        .into_iter()
        .map(|bytes| ArchiveReader::read_owned(bytes).unwrap())
        .collect()
}

#[test]
fn common_link_callbacks_preserve_order_files_and_old_byte_apis() {
    for version in [
        ArchiveVersion::Rar20,
        ArchiveVersion::Rar40,
        ArchiveVersion::Rar50,
    ] {
        for (store, solid) in [(true, false), (false, false), (false, true)] {
            let archive = fixture(version, store, solid);
            for volumes in [false, true] {
                for options in [
                    ArchiveReadOptions::new(),
                    ArchiveReadOptions::new().with_max_reader_workspace_bytes(16 * 1024 * 1024),
                    ArchiveReadOptions::new().with_max_total_output_bytes(606),
                ] {
                    let order = RefCell::new(Vec::new());
                    let files = RefCell::new(Vec::new());
                    let open = |meta: &rars::ExtractedEntryMeta| -> rars::Result<Box<dyn Write>> {
                        order.borrow_mut().push(meta.name.clone());
                        assert_ne!(meta.name, b"link");
                        let data = Rc::new(RefCell::new(Vec::new()));
                        files.borrow_mut().push(data.clone());
                        Ok(Box::new(Capture(data)))
                    };
                    let mut called = 0;
                    let link = |meta: &rars::ExtractedEntryMeta, link: ExtractedLink<'_>| {
                        called += 1;
                        order.borrow_mut().push(meta.name.clone());
                        assert_eq!(
                            link,
                            ExtractedLink::Symlink {
                                target: b"before",
                                directory: false
                            }
                        );
                        Ok(())
                    };
                    if volumes {
                        rars::extract_volumes_with_links(
                            std::slice::from_ref(&archive),
                            options,
                            open,
                            link,
                        )
                        .unwrap();
                    } else {
                        archive.extract_with_links(options, open, link).unwrap();
                    }
                    assert_eq!(called, 1);
                    assert_eq!(
                        *order.borrow(),
                        [b"before".to_vec(), b"link".to_vec(), b"after".to_vec()]
                    );
                    for data in files.into_inner() {
                        assert_eq!(*data.borrow(), b"hello ".repeat(50));
                    }
                }
            }
            let mut old_names = Vec::new();
            archive
                .extract_to(None, |meta| {
                    old_names.push(meta.name.clone());
                    Ok(Box::new(io::sink()))
                })
                .unwrap();
            assert_eq!(
                old_names.contains(&b"link".to_vec()),
                version != ArchiveVersion::Rar50
            );
        }
    }
}

#[test]
fn split_link_targets_are_reported_once_after_integrity_verification() {
    let target = vec![b'x'; 300];
    let mut archives = raw_link(&target, true);
    assert!(archives.len() > 1);
    let mut called = 0;
    rars::extract_volumes_with_links(
        &archives,
        ArchiveReadOptions::new(),
        |_| panic!("link opened as file"),
        |meta, link| {
            assert_eq!(meta.name, b"link");
            assert_eq!(link.target(), target);
            called += 1;
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(called, 1);
    if let Archive::Rar15To40(a) = archives.last_mut().unwrap() {
        for block in &mut a.blocks {
            if let rars::rar15_40::Block::File(file) = block {
                file.file_crc ^= 1;
            }
        }
    }
    assert!(rars::extract_volumes_with_links(
        &archives,
        ArchiveReadOptions::new(),
        |_| panic!(),
        |_, _| panic!("bad CRC published")
    )
    .is_err());
}

#[test]
fn invalid_or_unadmitted_link_targets_never_reach_callbacks() {
    for (target, options) in [
        (Vec::new(), ArchiveReadOptions::new()),
        (b"bad\0target".to_vec(), ArchiveReadOptions::new()),
        (vec![b'x'; 65537], ArchiveReadOptions::new()),
        (
            vec![b'x'; 32],
            ArchiveReadOptions::new().with_max_reader_workspace_bytes(8),
        ),
        (
            vec![b'x'; 32],
            ArchiveReadOptions::new().with_max_member_output_bytes(8),
        ),
        (
            vec![b'x'; 32],
            ArchiveReadOptions::new().with_max_total_output_bytes(8),
        ),
    ] {
        let archive = raw_link(&target, false).pop().unwrap();
        for volumes in [false, true] {
            let open = |_: &rars::ExtractedEntryMeta| -> rars::Result<Box<dyn Write>> {
                panic!("link opened as file")
            };
            let link = |_: &rars::ExtractedEntryMeta, _: ExtractedLink<'_>| -> rars::Result<()> {
                panic!("invalid link callback")
            };
            let result = if volumes {
                rars::extract_volumes_with_links(
                    std::slice::from_ref(&archive),
                    options,
                    open,
                    link,
                )
            } else {
                archive.extract_with_links(options, open, link)
            };
            assert!(
                result.is_err(),
                "target len {} volumes={volumes}",
                target.len()
            );
        }
    }
}

#[test]
fn legacy_target_bytes_and_beos_inspection_compatibility() {
    let mut archive = raw_link(b"native-\xff\\name", false).pop().unwrap();
    assert!(archive.members().next().unwrap().is_legacy_unix_symlink());
    archive
        .extract_with_links(
            ArchiveReadOptions::new(),
            |_| panic!(),
            |_, link| {
                assert_eq!(link.target(), b"native-\xff\\name");
                Ok(())
            },
        )
        .unwrap();
    if let Archive::Rar15To40(a) = &mut archive {
        for block in &mut a.blocks {
            if let rars::rar15_40::Block::File(file) = block {
                file.host_os = 5;
            }
        }
    }
    // Existing inspection/readlink APIs keep their broader Unix-mode behavior;
    // actual extraction agrees with UnRAR and only creates links for host 3.
    assert!(archive.members().next().unwrap().is_legacy_unix_symlink());
    assert_eq!(
        archive.legacy_symlink_target_at(0, None).unwrap(),
        Some(b"native-\xff\\name".to_vec())
    );
    let mut opened = 0;
    archive
        .extract_with_links(
            ArchiveReadOptions::new(),
            |_| {
                opened += 1;
                Ok(Box::new(io::sink()))
            },
            |_, _| panic!("BeOS entry treated as Unix link"),
        )
        .unwrap();
    assert_eq!(opened, 1);
}

#[test]
fn compressed_legacy_link_uses_the_shared_decoder() {
    use rars::rar15_40::{write_compressed_archive, FileEntry, WriterOptions};
    let target = b"target/".repeat(30);
    for version in [ArchiveVersion::Rar20, ArchiveVersion::Rar40] {
        let entry = FileEntry {
            name: b"link",
            data: &target,
            file_time: 0,
            file_attr: 0o120777,
            host_os: 3,
            password: None,
            file_comment: None,
        };
        let bytes = write_compressed_archive(
            &[entry],
            WriterOptions::new(version, rars::FeatureSet::default()),
        )
        .unwrap();
        let archive = ArchiveReader::read_owned(bytes).unwrap();
        assert!(!archive.members().next().unwrap().meta.is_stored);
        for volumes in [false, true] {
            let mut called = false;
            let link = |_: &rars::ExtractedEntryMeta, link: ExtractedLink<'_>| {
                called = true;
                assert_eq!(link.target(), target);
                Ok(())
            };
            if volumes {
                rars::extract_volumes_with_links(
                    std::slice::from_ref(&archive),
                    ArchiveReadOptions::new(),
                    |_| panic!(),
                    link,
                )
                .unwrap();
            } else {
                archive
                    .extract_with_links(ArchiveReadOptions::new(), |_| panic!(), link)
                    .unwrap();
            }
            assert!(called);
        }
    }
}

#[test]
fn cancellation_stops_link_and_later_callbacks() {
    let archive = fixture(ArchiveVersion::Rar40, false, true);
    let token = rars::ReadCancellation::new();
    let result = archive.extract_with_links(
        ArchiveReadOptions::new().with_cancellation(&token),
        |meta| {
            assert_eq!(meta.name, b"before");
            token.cancel();
            Ok(Box::new(io::sink()))
        },
        |_, _| panic!("cancelled link published"),
    );
    assert_eq!(result.unwrap_err().kind(), rars::ErrorKind::Cancelled);
}

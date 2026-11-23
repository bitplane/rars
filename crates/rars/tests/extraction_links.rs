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
            // 128, plus the 13 bytes a RAR 3.93-style end block adds, keeps the same split.
            141,
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

/// What one extraction reported: callbacks in order, the output of each member
/// that did not fail, and the error that ended it.
type Run = (Vec<String>, Vec<(Vec<u8>, Vec<u8>)>, Result<(), String>);

fn run_with_links(archive: &Archive, options: ArchiveReadOptions<'_>, handler: bool) -> Run {
    let events = std::sync::Mutex::new(Vec::new());
    let failed = std::sync::Mutex::new(Vec::new());
    let outputs = RefCell::new(Vec::new());
    let on_error = |member: &rars::ArchiveMember, error: &rars::Error| {
        let name = String::from_utf8_lossy(&member.meta.name);
        let event = format!("fail {name} {:?}", error.kind());
        events.lock().unwrap().push(event);
        failed.lock().unwrap().push(member.meta.name.clone());
        Ok(rars::ExtractionErrorAction::Continue)
    };
    let options = options.with_rar50_buffered_decode_limit(4096);
    let options = if handler {
        options.with_member_error_handler(&on_error)
    } else {
        options
    };
    let result = archive.extract_with_links(
        options,
        |meta| {
            let name = String::from_utf8_lossy(&meta.name).into_owned();
            events.lock().unwrap().push(format!("open {name}"));
            let data = Rc::new(RefCell::new(Vec::new()));
            outputs.borrow_mut().push((meta.name.clone(), data.clone()));
            Ok(Box::new(Capture(data)))
        },
        |meta, link| {
            let name = String::from_utf8_lossy(&meta.name);
            let target = String::from_utf8_lossy(link.target());
            events.lock().unwrap().push(format!("link {name} {target}"));
            Ok(())
        },
    );
    let mut failed = failed.into_inner().unwrap();
    let result = result.map_err(|error| {
        if let Some((name, _)) = error.entry_context() {
            failed.push(name.to_vec());
        }
        format!("{:?} {error}", error.kind())
    });
    // Sequential extraction opens a buffered member before it fails, and the
    // batches never do. Either way its output is unverified, so drop both.
    let opened_failed = |name: &[u8]| format!("open {}", String::from_utf8_lossy(name));
    let mut events = events.into_inner().unwrap();
    events.retain(|event| !failed.iter().any(|name| *event == opened_failed(name)));
    let outputs = outputs
        .into_inner()
        .into_iter()
        .filter(|(name, _)| !failed.contains(name))
        .map(|(name, data)| (name, data.take()))
        .collect();
    (events, outputs, result)
}

/// RAR 5 extraction with links decodes members in parallel, so its callbacks,
/// output and failures must match sequential extraction at any thread count,
/// with members both buffered and streamed, and failures in both.
#[test]
fn rar50_links_match_sequential_extraction_at_any_thread_count() {
    let mut builder = Builder::new(ArchiveVersion::Rar50);
    let mut sources = Vec::new();
    for index in 0..24u32 {
        let name = format!("file{index:02}").into_bytes();
        // Every fifth member is over the buffered limit used, so it streams.
        let len = if index % 5 == 0 {
            40_000
        } else {
            300 + 37 * index
        };
        let data: Vec<u8> = (0..len)
            .map(|n| (n * 7 / (index + 3) + index) as u8)
            .collect();
        builder
            .add_bytes(name.clone(), data.clone(), None, None)
            .unwrap();
        if index % 4 == 1 {
            let link = format!("link{index:02}").into_bytes();
            builder
                .add_unix_symlink(link, name.clone(), false, None, None)
                .unwrap();
        }
        sources.push((name, data));
    }
    let clean = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
    let mut damaged = clean.clone();
    if let Archive::Rar50Plus(archive) = &mut damaged {
        for block in &mut archive.blocks {
            if let rars::rar50::Block::File(file) = block {
                // One buffered and one streamed member fail their checksums.
                if file.name == b"file03" || file.name == b"file10" {
                    file.hash = None;
                    file.data_crc32 = Some(file.data_crc32.unwrap() ^ 1);
                }
            }
        }
    }

    for (archive, handler) in [(&clean, false), (&damaged, true), (&damaged, false)] {
        let sequential = run_with_links(
            archive,
            // A total output limit keeps extraction sequential.
            ArchiveReadOptions::new().with_max_total_output_bytes(u64::MAX),
            handler,
        );
        let fails: Vec<&String> = sequential
            .0
            .iter()
            .filter(|event| event.starts_with("fail"))
            .collect();
        if std::ptr::eq(archive, &clean) {
            assert_eq!(sequential.2, Ok(()));
            assert_eq!(sequential.1, sources);
            assert!(fails.is_empty());
        } else if handler {
            assert_eq!(sequential.2, Ok(()));
            assert_eq!(
                fails,
                [
                    "fail file03 ChecksumMismatch",
                    "fail file10 ChecksumMismatch"
                ]
            );
        } else {
            assert!(sequential.2.as_ref().unwrap_err().contains("file03"));
        }
        for threads in [1, 2, 8] {
            for limited in [false, true] {
                let options = ArchiveReadOptions::new().with_threads(threads);
                let options = if limited {
                    options.with_max_reader_workspace_bytes(64 * 1024 * 1024)
                } else {
                    options
                };
                assert_eq!(
                    run_with_links(archive, options, handler),
                    sequential,
                    "threads={threads} limited={limited} handler={handler}"
                );
            }
        }
    }
}

/// A writer whose output is read back once it is dropped, from any thread.
struct SharedCapture(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
impl Write for SharedCapture {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// What a settled extraction reported: its callbacks other than opens, in
/// order, the output of each member settled as verified, and the error that
/// ended it.
type SettledRun = (Vec<String>, Vec<(Vec<u8>, Vec<u8>)>, Result<(), String>);

/// Also returns the most members open and not yet settled at once.
fn run_settled(
    archive: &Archive,
    options: ArchiveReadOptions<'_>,
    handler: bool,
) -> (SettledRun, usize) {
    let Archive::Rar50Plus(rar50) = archive else {
        unreachable!("settled extraction is RAR 5 only")
    };
    let order: Vec<Vec<u8>> = archive.members().map(|m| m.meta.name.clone()).collect();
    let events = std::sync::Mutex::new(Vec::new());
    let opened = RefCell::new(Vec::new());
    let unsettled = RefCell::new(std::collections::VecDeque::new());
    let most_unsettled = std::cell::Cell::new(0);
    let verified = RefCell::new(Vec::new());
    let on_error = |member: &rars::ArchiveMember, error: &rars::Error| {
        let name = String::from_utf8_lossy(&member.meta.name);
        let event = format!("fail {name} {:?}", error.kind());
        events.lock().unwrap().push(event);
        Ok(rars::ExtractionErrorAction::Continue)
    };
    let options = options.with_rar50_buffered_decode_limit(4096);
    let options = if handler {
        options.with_member_error_handler(&on_error)
    } else {
        options
    };
    let result = rars::output_links::extract_rar50_settled_with_links(
        rar50,
        options,
        |meta| {
            let data = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let mut opened = opened.borrow_mut();
            opened.push((meta.name.clone(), data.clone()));
            let mut unsettled = unsettled.borrow_mut();
            unsettled.push_back(opened.len() - 1);
            most_unsettled.set(most_unsettled.get().max(unsettled.len()));
            Ok(Box::new(SharedCapture(data)))
        },
        |meta, link| {
            assert!(
                unsettled.borrow().is_empty(),
                "a link waits for the members opened before it to settle"
            );
            let name = String::from_utf8_lossy(&meta.name);
            let target = String::from_utf8_lossy(link.target());
            events.lock().unwrap().push(format!("link {name} {target}"));
            Ok(())
        },
        |meta, ok| {
            let index = unsettled
                .borrow_mut()
                .pop_front()
                .expect("only opened members settle");
            let opened = opened.borrow();
            let (name, data) = &opened[index];
            assert_eq!(*name, meta.name, "members settle in the order they open");
            let shown = String::from_utf8_lossy(name);
            events.lock().unwrap().push(format!("settle {shown} {ok}"));
            if ok {
                assert_eq!(
                    std::sync::Arc::strong_count(data),
                    1,
                    "a verified member's writer is dropped before it settles"
                );
                let output = data.lock().unwrap().clone();
                verified.borrow_mut().push((name.clone(), output));
            }
            Ok(())
        },
    );
    // Members open in archive order, each once.
    let positions: Vec<usize> = opened
        .borrow()
        .iter()
        .map(|(name, _)| order.iter().position(|n| n == name).unwrap())
        .collect();
    assert!(positions.windows(2).all(|pair| pair[0] < pair[1]));
    let mut events = events.into_inner().unwrap();
    // A failed member settles just before the handler hears of it.
    for (index, event) in events.iter().enumerate() {
        if let Some(rest) = event.strip_prefix("fail ") {
            let name = rest.split(' ').next().unwrap();
            let settled = format!("settle {name} false");
            if events.contains(&settled) {
                assert_eq!(events[index - 1], settled, "{events:?}");
            }
        }
    }
    // Sequential extraction opens a member before it fails, and the publishing
    // batches never do, so only the members that verified are compared.
    events.retain(|event| !event.ends_with(" false"));
    let result = result.map_err(|error| format!("{:?} {error}", error.kind()));
    (
        (events, verified.into_inner(), result),
        most_unsettled.get(),
    )
}

/// Settled extraction writes members on workers and opens later ones before
/// earlier ones verify, so what verifies, the links and the failures must
/// match sequential extraction at any thread count, with members buffered
/// and streamed and failures in both.
#[test]
fn rar50_settled_extraction_matches_sequential_at_any_thread_count() {
    let mut builder = Builder::new(ArchiveVersion::Rar50);
    let mut sources = Vec::new();
    for index in 0..24u32 {
        let name = format!("file{index:02}").into_bytes();
        // Most of them stream, past the buffered limit used.
        let len = if index % 3 == 2 {
            300 + 37 * index
        } else {
            20_000 + 1_000 * index
        };
        let data: Vec<u8> = (0..len)
            .map(|n| (n * 7 / (index + 3) + index) as u8)
            .collect();
        builder
            .add_bytes(name.clone(), data.clone(), None, None)
            .unwrap();
        if index % 7 == 1 {
            let link = format!("link{index:02}").into_bytes();
            builder
                .add_unix_symlink(link, name.clone(), false, None, None)
                .unwrap();
        }
        sources.push((name, data));
    }
    let clean = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap();
    let mut damaged = clean.clone();
    if let Archive::Rar50Plus(archive) = &mut damaged {
        for block in &mut archive.blocks {
            if let rars::rar50::Block::File(file) = block {
                // Streamed members amid others fail, and one buffered one.
                if [&b"file06"[..], b"file07", b"file11", b"file19"].contains(&&file.name[..]) {
                    file.hash = None;
                    file.data_crc32 = Some(file.data_crc32.unwrap() ^ 1);
                }
            }
        }
    }

    for (archive, handler) in [(&clean, false), (&damaged, true), (&damaged, false)] {
        let sequential = run_settled(
            archive,
            // A total output limit keeps extraction sequential.
            ArchiveReadOptions::new().with_max_total_output_bytes(u64::MAX),
            handler,
        )
        .0;
        let fails: Vec<&String> = sequential
            .0
            .iter()
            .filter(|event| event.starts_with("fail"))
            .collect();
        if std::ptr::eq(archive, &clean) {
            assert_eq!(sequential.2, Ok(()));
            assert_eq!(sequential.1, sources);
            assert!(fails.is_empty());
        } else if handler {
            assert_eq!(sequential.2, Ok(()));
            assert_eq!(
                fails,
                [
                    "fail file06 ChecksumMismatch",
                    "fail file07 ChecksumMismatch",
                    "fail file11 ChecksumMismatch",
                    "fail file19 ChecksumMismatch",
                ]
            );
            let expected: Vec<_> = sources
                .iter()
                .filter(|(name, _)| {
                    !fails
                        .iter()
                        .any(|f| f.contains(&*String::from_utf8_lossy(name)))
                })
                .cloned()
                .collect();
            assert_eq!(sequential.1, expected);
        } else {
            assert!(sequential.2.as_ref().unwrap_err().contains("file06"));
            assert_eq!(sequential.1, sources[..6]);
        }
        for threads in [1, 2, 8] {
            for limited in [false, true] {
                let options = ArchiveReadOptions::new().with_threads(threads);
                let options = if limited {
                    options.with_max_reader_workspace_bytes(64 * 1024 * 1024)
                } else {
                    options
                };
                let (run, most_unsettled) = run_settled(archive, options, handler);
                assert_eq!(
                    run, sequential,
                    "threads={threads} limited={limited} handler={handler}"
                );
                // Unlimited, later members are opened while earlier ones run.
                if threads > 1 && !limited && std::ptr::eq(archive, &clean) {
                    assert!(most_unsettled > 1, "threads={threads}");
                } else if threads == 1 || limited {
                    assert_eq!(most_unsettled, 1, "threads={threads}");
                }
            }
        }
    }
}

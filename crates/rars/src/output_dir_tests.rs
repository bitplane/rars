use super::*;

fn mode(overwrite: OverwritePolicy) -> DirMode {
    DirMode {
        overwrite,
        in_place: false,
        restore_times: false,
        restore_modes: false,
        flatten: false,
        exists_hint: "",
    }
}

const THREADS: [usize; 3] = [1, 2, 8];

fn capped<T>(threads: usize, run: impl FnOnce() -> T) -> T {
    let _cap = crate::parallel::ThreadCap::set(Some(threads));
    run()
}

fn file(name: &str) -> crate::ExtractedEntryMeta {
    crate::ExtractedEntryMeta::new(name.as_bytes().to_vec(), None, 0, false)
}

fn dir(name: &str) -> crate::ExtractedEntryMeta {
    crate::ExtractedEntryMeta::new(name.as_bytes().to_vec(), None, 0, true)
}

fn write(outputs: &mut DirOutputs<'_>, meta: &crate::ExtractedEntryMeta, bytes: &[u8]) {
    let mut writer = outputs.open_settled(meta).unwrap();
    writer.write_all(bytes).unwrap();
}

fn listing(root: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(root)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[test]
fn settling_publishes_verified_members_and_drops_failed_ones() {
    for threads in THREADS {
        capped(threads, || {
            let root = crate::scratch::case("dir-outputs-settled");
            let mut outputs = DirOutputs::new(
                &root,
                crate::ArchiveFamily::Rar50Plus,
                None,
                mode(OverwritePolicy::Never),
                None,
            );
            write(&mut outputs, &file("kept"), b"kept");
            write(&mut outputs, &file("broken"), b"broken");
            write(&mut outputs, &file("later"), b"later");
            assert!(
                !root.join("kept").exists(),
                "nothing is published before it settles"
            );
            outputs.settle(true).unwrap();
            outputs.settle(false).unwrap();
            outputs.settle(true).unwrap();
            let extracted = outputs.finish(Ok(())).unwrap();
            assert_eq!(listing(&root), ["kept", "later"]);
            assert_eq!(fs::read(root.join("kept")).unwrap(), b"kept");
            assert_eq!(extracted.paths, [root.join("kept"), root.join("later")]);
        });
    }
}

#[test]
fn a_member_on_the_path_of_an_unsettled_one_is_refused_only_once_that_one_publishes() {
    for threads in THREADS {
        capped(threads, || {
            for first_verified in [true, false] {
                let root = crate::scratch::case("dir-outputs-settled-same-path");
                let mut outputs = DirOutputs::new(
                    &root,
                    crate::ArchiveFamily::Rar50Plus,
                    None,
                    mode(OverwritePolicy::Never),
                    None,
                );
                write(&mut outputs, &file("same"), b"first");
                write(&mut outputs, &file("same"), b"second");
                outputs.settle(first_verified).unwrap();
                let second = outputs.settle(true);
                let extracted = outputs.finish(Ok(())).unwrap();
                if first_verified {
                    let error = second.unwrap_err().to_string();
                    assert!(error.contains("already exists"), "{error}");
                    assert_eq!(fs::read(root.join("same")).unwrap(), b"first");
                } else {
                    second.unwrap();
                    assert_eq!(fs::read(root.join("same")).unwrap(), b"second");
                }
                assert_eq!(extracted.paths, [root.join("same")]);
                assert_eq!(listing(&root), ["same"]);
            }
        });
    }
}

#[test]
fn a_directory_is_made_once_the_members_before_it_settle() {
    for threads in THREADS {
        capped(threads, || {
            let root = crate::scratch::case("dir-outputs-settled-directory");
            let mut outputs = DirOutputs::new(
                &root,
                crate::ArchiveFamily::Rar50Plus,
                None,
                mode(OverwritePolicy::Always),
                None,
            );
            write(&mut outputs, &file("taken"), b"file");
            outputs.open_settled(&dir("taken")).unwrap();
            outputs.settle(true).unwrap();
            let settled = outputs.settle(true);
            let finished = outputs.finish(Ok(()));
            // Published on a thread of its own, it fails at the settle or at the end.
            let error = settled
                .err()
                .or(finished.err())
                .expect("the directory is refused");
            assert!(
                matches!(&error, crate::Error::Io(error) if error.kind == io::ErrorKind::AlreadyExists),
                "{error}"
            );
            assert_eq!(fs::read(root.join("taken")).unwrap(), b"file");
        });
    }
}

#[test]
fn a_file_on_the_path_of_an_unsettled_directory_is_refused_as_already_there() {
    for threads in THREADS {
        capped(threads, || {
            let root = crate::scratch::case("dir-outputs-settled-file-on-directory");
            let mut outputs = DirOutputs::new(
                &root,
                crate::ArchiveFamily::Rar50Plus,
                None,
                mode(OverwritePolicy::Never),
                None,
            );
            outputs.open_settled(&dir("taken")).unwrap();
            write(&mut outputs, &file("taken"), b"file");
            outputs.settle(true).unwrap();
            let error = outputs.settle(true).unwrap_err().to_string();
            outputs.finish(Ok(())).unwrap();
            assert!(error.contains("taken already exists"), "{error}");
            assert!(root.join("taken").is_dir());
        });
    }
}

fn open_and_write(outputs: &mut DirOutputs<'_>, meta: &crate::ExtractedEntryMeta, bytes: &[u8]) {
    outputs.open(meta).unwrap().write_all(bytes).unwrap();
}

#[test]
fn a_member_on_the_path_of_one_still_publishing_is_refused_as_already_there() {
    for threads in THREADS {
        capped(threads, || {
            let root = crate::scratch::case("dir-outputs-queued-same-path");
            let mut outputs = DirOutputs::new(
                &root,
                crate::ArchiveFamily::Rar50Plus,
                None,
                mode(OverwritePolicy::Never),
                None,
            );
            open_and_write(&mut outputs, &file("same"), b"first");
            let error = match outputs.open(&file("same")) {
                Ok(_) => panic!("threads={threads}: the second member opened"),
                Err(error) => error.to_string(),
            };
            let extracted = outputs.finish(Ok(())).unwrap();
            assert!(
                error.contains("same already exists"),
                "threads={threads}: {error}"
            );
            assert_eq!(fs::read(root.join("same")).unwrap(), b"first");
            assert_eq!(extracted.paths, [root.join("same")]);
        });
    }
}

#[test]
fn a_file_on_the_path_of_a_directory_still_publishing_is_refused_as_already_there() {
    for threads in THREADS {
        capped(threads, || {
            let root = crate::scratch::case("dir-outputs-queued-file-on-directory");
            let mut outputs = DirOutputs::new(
                &root,
                crate::ArchiveFamily::Rar50Plus,
                None,
                mode(OverwritePolicy::Never),
                None,
            );
            open_and_write(&mut outputs, &file("a/b"), b"inner");
            let error = match outputs.open(&file("a")) {
                Ok(_) => panic!("threads={threads}: the file opened"),
                Err(error) => error.to_string(),
            };
            outputs.finish(Ok(())).unwrap();
            assert!(
                error.contains("a already exists"),
                "threads={threads}: {error}"
            );
            assert_eq!(fs::read(root.join("a/b")).unwrap(), b"inner");
        });
    }
}

#[test]
fn members_on_one_path_publish_in_archive_order() {
    for overwrite in [OverwritePolicy::Always, OverwritePolicy::Rename] {
        for threads in THREADS {
            capped(threads, || {
                let root = crate::scratch::case("dir-outputs-queued-repeats");
                let mut outputs = DirOutputs::new(
                    &root,
                    crate::ArchiveFamily::Rar50Plus,
                    None,
                    mode(overwrite),
                    None,
                );
                let mut refused = None;
                for (index, name) in ["x", "y", "x", "x"].into_iter().enumerate() {
                    match outputs.open(&file(name)) {
                        Ok(mut writer) => writer.write_all(index.to_string().as_bytes()).unwrap(),
                        Err(error) => {
                            refused = Some(error.to_string());
                            break;
                        }
                    }
                }
                outputs.finish(Ok(())).unwrap();
                let context = format!("{overwrite:?} threads={threads}");
                if overwrite == OverwritePolicy::Always {
                    assert_eq!(refused, None, "{context}");
                    assert_eq!(listing(&root), ["x", "y"], "{context}");
                    assert_eq!(fs::read(root.join("x")).unwrap(), b"3", "{context}");
                } else {
                    let error = refused.expect("a repeat is refused under Rename");
                    assert!(error.contains("same output path"), "{context}: {error}");
                    assert_eq!(listing(&root), ["x", "y"], "{context}");
                    assert_eq!(fs::read(root.join("x")).unwrap(), b"0", "{context}");
                }
            });
        }
    }
}

#[test]
fn a_staged_file_keeps_its_time_once_published() {
    let modified = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_600_000_000);
    for threads in THREADS {
        capped(threads, || {
            let root = crate::scratch::case("dir-outputs-queued-times");
            let mut timed = mode(OverwritePolicy::Never);
            timed.restore_times = true;
            let mut outputs =
                DirOutputs::new(&root, crate::ArchiveFamily::Rar50Plus, None, timed, None);
            for name in ["d/one", "d/two", "three"] {
                let meta = crate::ExtractedEntryMeta::new(
                    name.as_bytes().to_vec(),
                    Some(crate::Timestamp::from_unix_seconds(1_600_000_000)),
                    0,
                    false,
                );
                open_and_write(&mut outputs, &meta, name.as_bytes());
            }
            outputs.finish(Ok(())).unwrap();
            for name in ["d/one", "d/two", "three"] {
                let published = fs::metadata(root.join(name)).unwrap().modified().unwrap();
                assert_eq!(published, modified, "threads={threads} {name}");
            }
        });
    }
}

#[test]
fn a_file_on_a_directory_an_unsettled_members_path_makes_is_refused_as_already_there() {
    for threads in THREADS {
        capped(threads, || {
            let root = crate::scratch::case("dir-outputs-settled-file-over-made-directory");
            let mut outputs = DirOutputs::new(
                &root,
                crate::ArchiveFamily::Rar50Plus,
                None,
                mode(OverwritePolicy::Never),
                None,
            );
            write(&mut outputs, &file("a/b/c"), b"inner");
            write(&mut outputs, &file("a/b"), b"outer");
            outputs.settle(true).unwrap();
            let error = outputs.settle(true).unwrap_err().to_string();
            outputs.finish(Ok(())).unwrap();
            assert!(
                error.contains("a/b already exists"),
                "threads={threads}: {error}"
            );
            assert_eq!(fs::read(root.join("a/b/c")).unwrap(), b"inner");
        });
    }
}

#[cfg(any(target_vendor = "apple", target_os = "linux", target_os = "android"))]
fn plant_next_staged(outputs: &DirOutputs<'_>) {
    let storage = outputs.storage.as_ref().expect("a member staged already");
    let (_, files) = storage.files.as_ref().expect("staged by descriptor");
    fs::write(files.join(outputs.staged.to_string()), b"planted").unwrap();
}

#[cfg(any(target_vendor = "apple", target_os = "linux", target_os = "android"))]
#[test]
fn a_staged_file_that_cant_be_created_fails_its_write_not_its_open() {
    for settled in [false, true] {
        for threads in THREADS {
            capped(threads, || {
                let root = crate::scratch::case("dir-outputs-staged-create-fails");
                let mut outputs = DirOutputs::new(
                    &root,
                    crate::ArchiveFamily::Rar50Plus,
                    None,
                    mode(OverwritePolicy::Never),
                    None,
                );
                let context = format!("settled={settled} threads={threads}");
                if settled {
                    write(&mut outputs, &file("first"), b"first");
                    plant_next_staged(&outputs);
                    let mut writer = outputs
                        .open_settled(&file("second"))
                        .expect("opening creates no file");
                    // Written on another thread, as the decode workers do.
                    let error = std::thread::spawn(move || writer.write_all(b"second"))
                        .join()
                        .unwrap()
                        .unwrap_err();
                    assert_eq!(error.kind(), io::ErrorKind::AlreadyExists, "{context}");
                    outputs.settle(true).unwrap();
                    outputs.settle(false).unwrap();
                    outputs.finish(Ok(())).unwrap();
                } else {
                    open_and_write(&mut outputs, &file("first"), b"first");
                    plant_next_staged(&outputs);
                    let mut writer = outputs
                        .open(&file("second"))
                        .expect("opening creates no file");
                    let error = writer.write_all(b"second").unwrap_err();
                    drop(writer);
                    assert_eq!(error.kind(), io::ErrorKind::AlreadyExists, "{context}");
                    outputs.finish(Err(error.into())).unwrap_err();
                }
                assert_eq!(listing(&root), ["first"], "{context}");
            });
        }
    }
}

#[test]
fn an_empty_member_nothing_writes_is_published_with_its_time() {
    let modified = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_600_000_000);
    let meta = |name: &str| {
        crate::ExtractedEntryMeta::new(
            name.as_bytes().to_vec(),
            Some(crate::Timestamp::from_unix_seconds(1_600_000_000)),
            0,
            false,
        )
    };
    for settled in [false, true] {
        for threads in THREADS {
            capped(threads, || {
                let root = crate::scratch::case("dir-outputs-empty-member");
                let mut timed = mode(OverwritePolicy::Never);
                timed.restore_times = true;
                let mut outputs =
                    DirOutputs::new(&root, crate::ArchiveFamily::Rar50Plus, None, timed, None);
                for name in ["one", "two"] {
                    if settled {
                        drop(outputs.open_settled(&meta(name)).unwrap());
                        outputs.settle(true).unwrap();
                    } else {
                        drop(outputs.open(&meta(name)).unwrap());
                    }
                }
                outputs.finish(Ok(())).unwrap();
                for name in ["one", "two"] {
                    let context = format!("settled={settled} threads={threads} {name}");
                    let published = fs::metadata(root.join(name)).expect(&context);
                    assert_eq!(published.len(), 0, "{context}");
                    assert_eq!(published.modified().unwrap(), modified, "{context}");
                }
            });
        }
    }
}

#[cfg(any(target_vendor = "apple", target_os = "linux", target_os = "android"))]
#[test]
fn an_empty_member_whose_staged_file_cant_be_created_fails_to_publish_saying_so() {
    for threads in THREADS {
        capped(threads, || {
            let root = crate::scratch::case("dir-outputs-empty-create-fails");
            let mut outputs = DirOutputs::new(
                &root,
                crate::ArchiveFamily::Rar50Plus,
                None,
                mode(OverwritePolicy::Never),
                None,
            );
            write(&mut outputs, &file("first"), b"first");
            plant_next_staged(&outputs);
            drop(outputs.open_settled(&file("empty")).unwrap());
            outputs.settle(true).unwrap();
            let settled = outputs.settle(true);
            let finished = outputs.finish(Ok(()));
            let error = settled
                .err()
                .or(finished.err())
                .expect("the empty member is refused")
                .to_string();
            assert!(
                error.contains("the staged file could not be created"),
                "threads={threads}: {error}"
            );
            assert_eq!(listing(&root), ["first"], "threads={threads}");
        });
    }
}

#[cfg(unix)]
#[test]
fn modes_go_on_through_descriptors_except_unreadable_files_and_directories() {
    let unix = |name: &str, mode: u64, directory: bool| {
        crate::ExtractedEntryMeta::new(name.as_bytes().to_vec(), None, mode, directory)
            .with_attr_source(crate::AttrSource::Unix)
    };
    for threads in THREADS {
        capped(threads, || {
            for (settled, in_place) in [(false, false), (true, false), (false, true)] {
                let root = crate::scratch::case("dir-outputs-modes-by-descriptor");
                let mut moded = mode(OverwritePolicy::Never);
                moded.restore_modes = true;
                moded.in_place = in_place;
                let mut outputs =
                    DirOutputs::new(&root, crate::ArchiveFamily::Rar50Plus, None, moded, None);
                let members = [
                    unix("d", 0o040700, true),
                    unix("d/604", 0o100604, false),
                    unix("777", 0o100777, false),
                    unix("600", 0o100600, false),
                    unix("200", 0o100200, false),
                ];
                for meta in &members {
                    if settled {
                        write(&mut outputs, meta, b"x");
                        outputs.settle(true).unwrap();
                    } else {
                        open_and_write(&mut outputs, meta, b"x");
                    }
                }
                // Settling is only for archives without links.
                let links = [
                    ("hard", 0o100600, ExtractedLink::HardLink { target: b"600" }),
                    ("copy", 0o100600, ExtractedLink::FileCopy { target: b"600" }),
                    (
                        "copy200",
                        0o100200,
                        ExtractedLink::FileCopy { target: b"200" },
                    ),
                ];
                if !settled {
                    for (name, mode, link) in links {
                        outputs.link(&unix(name, mode, false), link).unwrap();
                    }
                }
                outputs.publish_pending().unwrap();
                let mut by_path = vec![root.join("200")];
                if !settled {
                    by_path.push(root.join("copy200"));
                }
                by_path.push(root.join("d"));
                assert_eq!(
                    outputs.modes_by_path(),
                    by_path,
                    "threads={threads} settled={settled} in_place={in_place}"
                );
                outputs.finish(Ok(())).unwrap();
                let linked = [("hard", 0o600), ("copy", 0o600), ("copy200", 0o200)];
                for (name, mode) in [
                    ("d", 0o700),
                    ("d/604", 0o604),
                    ("777", 0o777),
                    ("600", 0o600),
                    ("200", 0o200),
                ]
                .into_iter()
                .chain(linked.into_iter().filter(|_| !settled))
                {
                    use std::os::unix::fs::PermissionsExt;
                    let found = fs::metadata(root.join(name)).unwrap().permissions().mode();
                    assert_eq!(found & 0o7777, mode, "{name} in_place={in_place}");
                }
            }
        });
    }
}

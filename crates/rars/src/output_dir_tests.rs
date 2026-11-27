use super::*;

fn mode(overwrite: OverwritePolicy) -> DirMode {
    DirMode {
        overwrite,
        in_place: false,
        restore_times: false,
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

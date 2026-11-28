use super::*;
use std::fs;
use std::io;
use std::path::PathBuf;

fn mode(overwrite: OverwritePolicy) -> DirMode {
    DirMode {
        overwrite,
        in_place: false,
        restore_times: false,
        restore_modes: false,
        symlinks: crate::SymlinkPolicy::Inside,
        flatten: false,
        exists_hint: "",
    }
}

const THREADS: [usize; 3] = [1, 2, 8];

fn capped<T>(threads: usize, run: impl FnOnce() -> T) -> T {
    let _cap = crate::parallel::ThreadCap::set(Some(threads));
    run()
}

fn outputs(root: &Path, mode: DirMode) -> DirExtraction<'_> {
    let mut outputs = DirExtraction::new(root, crate::ArchiveFamily::Rar50Plus, None, mode);
    // As RAR 5's write lane does: staged files are created by whoever writes them.
    outputs.written_elsewhere(true);
    outputs
}

fn file(name: &str) -> crate::ExtractedEntryMeta {
    crate::ExtractedEntryMeta::new(name.as_bytes().to_vec(), None, 0, false)
}

fn dir(name: &str) -> crate::ExtractedEntryMeta {
    crate::ExtractedEntryMeta::new(name.as_bytes().to_vec(), None, 0, true)
}

fn write(outputs: &mut DirExtraction<'_>, meta: &crate::ExtractedEntryMeta, bytes: &[u8]) {
    let mut writer = outputs.open(meta).unwrap();
    writer.write_all(bytes).unwrap();
}

fn open_and_write(outputs: &mut DirExtraction<'_>, meta: &crate::ExtractedEntryMeta, bytes: &[u8]) {
    write(outputs, meta, bytes);
    outputs.settle(Settled::Verified).unwrap();
}

fn listing(root: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(root)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

fn refused(opened: crate::Result<Box<dyn Write + Send>>) -> String {
    match opened {
        Ok(_) => panic!("the member opened"),
        Err(error) => error.to_string(),
    }
}

#[test]
fn settling_publishes_verified_members_and_drops_failed_ones() {
    for threads in THREADS {
        capped(threads, || {
            let root = crate::scratch::case("dir-extraction-settled");
            let mut outputs = outputs(&root, mode(OverwritePolicy::Never));
            write(&mut outputs, &file("kept"), b"kept");
            write(&mut outputs, &file("broken"), b"broken");
            write(&mut outputs, &file("later"), b"later");
            assert!(
                !root.join("kept").exists(),
                "nothing is published before it settles"
            );
            outputs.settle(Settled::Verified).unwrap();
            outputs.settle(Settled::Failed).unwrap();
            outputs.settle(Settled::Verified).unwrap();
            let extracted = outputs.finish(Ok(())).unwrap();
            assert_eq!(listing(&root), ["kept", "later"]);
            assert_eq!(fs::read(root.join("kept")).unwrap(), b"kept");
            assert_eq!(extracted.paths, [root.join("kept"), root.join("later")]);
        });
    }
}

#[test]
fn a_repeated_path_is_refused_as_it_opens_whatever_becomes_of_the_first() {
    for threads in THREADS {
        capped(threads, || {
            for first in [Settled::Verified, Settled::Failed] {
                let root = crate::scratch::case("dir-extraction-same-path");
                let mut outputs = outputs(&root, mode(OverwritePolicy::Never));
                write(&mut outputs, &file("same"), b"first");
                let error = refused(outputs.open(&file("same")));
                outputs.settle(first).unwrap();
                outputs.settle(Settled::Failed).unwrap();
                let extracted = outputs.finish(Ok(())).unwrap();
                assert!(error.contains("same output path"), "{error}");
                if first == Settled::Verified {
                    assert_eq!(fs::read(root.join("same")).unwrap(), b"first");
                    assert_eq!(extracted.paths, [root.join("same")]);
                } else {
                    assert_eq!(listing(&root), [] as [&str; 0]);
                }
            }
        });
    }
}

#[test]
fn a_directory_over_a_file_a_member_wrote_fails_to_publish() {
    for threads in THREADS {
        capped(threads, || {
            let root = crate::scratch::case("dir-extraction-directory-over-file");
            let mut outputs = outputs(&root, mode(OverwritePolicy::Always));
            write(&mut outputs, &file("taken"), b"file");
            // Repeats may land under `Always`, so publishing it finds the file.
            drop(outputs.open(&dir("taken")).unwrap());
            outputs.settle(Settled::Verified).unwrap();
            let settled = outputs.settle(Settled::Verified);
            let finished = outputs.finish(Ok(()));
            let error = settled
                .err()
                .or(finished.err())
                .expect("the directory is refused");
            assert_eq!(
                error.kind(),
                crate::ErrorKind::Io,
                "threads={threads}: {error}"
            );
            assert_eq!(fs::read(root.join("taken")).unwrap(), b"file");
        });
    }
}

#[test]
fn a_file_over_a_directory_a_member_made_is_refused_as_a_repeat() {
    for threads in THREADS {
        capped(threads, || {
            for settled in [false, true] {
                let root = crate::scratch::case("dir-extraction-file-over-directory");
                let mut outputs = outputs(&root, mode(OverwritePolicy::Never));
                drop(outputs.open(&dir("taken")).unwrap());
                if settled {
                    outputs.settle(Settled::Verified).unwrap();
                }
                let error = refused(outputs.open(&file("taken")));
                if !settled {
                    outputs.settle(Settled::Verified).unwrap();
                }
                outputs.settle(Settled::Failed).unwrap();
                outputs.finish(Ok(())).unwrap();
                assert!(error.contains("same output path"), "{error}");
                assert!(root.join("taken").is_dir());
            }
        });
    }
}

#[test]
fn a_file_where_a_member_made_a_directory_is_refused_as_a_repeat() {
    for threads in THREADS {
        capped(threads, || {
            for settled in [false, true] {
                let root = crate::scratch::case("dir-extraction-file-over-made-directory");
                let mut outputs = outputs(&root, mode(OverwritePolicy::Never));
                write(&mut outputs, &file("a/b/c"), b"inner");
                if settled {
                    outputs.settle(Settled::Verified).unwrap();
                }
                let opened = outputs.open(&file("a/b"));
                if !settled {
                    outputs.settle(Settled::Verified).unwrap();
                }
                let settled_second = match opened {
                    Ok(writer) => {
                        drop(writer);
                        outputs.settle(Settled::Verified).err()
                    }
                    Err(error) => {
                        outputs.settle(Settled::Failed).unwrap();
                        Some(error)
                    }
                };
                let finished = outputs.finish(Ok(()));
                let error = settled_second
                    .or(finished.err())
                    .expect("the file is refused")
                    .to_string();
                assert!(
                    error.contains("same output path"),
                    "settled={settled}: {error}"
                );
                assert_eq!(fs::read(root.join("a/b/c")).unwrap(), b"inner");
            }
        });
    }
}

#[test]
fn a_member_under_a_file_a_member_wrote_is_not_a_directory() {
    for threads in THREADS {
        capped(threads, || {
            let root = crate::scratch::case("dir-extraction-under-a-file");
            let mut outputs = outputs(&root, mode(OverwritePolicy::Always));
            open_and_write(&mut outputs, &file("a"), b"outer");
            let failed = match outputs.open(&file("a/b")) {
                Ok(writer) => {
                    drop(writer);
                    outputs.settle(Settled::Verified).err()
                }
                Err(error) => {
                    outputs.settle(Settled::Failed).unwrap();
                    Some(error)
                }
            };
            let finished = outputs.finish(Ok(()));
            let error = failed
                .or(finished.err())
                .expect("the member under a file is refused");
            assert_eq!(error.kind(), crate::ErrorKind::Io, "{error}");
            assert_eq!(fs::read(root.join("a")).unwrap(), b"outer");
        });
    }
}

#[test]
fn members_on_one_path_publish_in_archive_order() {
    for overwrite in [OverwritePolicy::Always, OverwritePolicy::Rename] {
        for threads in THREADS {
            capped(threads, || {
                let root = crate::scratch::case("dir-extraction-repeats");
                let mut outputs = outputs(&root, mode(overwrite));
                let mut refused = None;
                for (index, name) in ["x", "y", "x", "x"].into_iter().enumerate() {
                    match outputs.open(&file(name)) {
                        Ok(mut writer) => {
                            writer.write_all(index.to_string().as_bytes()).unwrap();
                            drop(writer);
                            outputs.settle(Settled::Verified).unwrap();
                        }
                        Err(error) => {
                            outputs.settle(Settled::Failed).unwrap();
                            refused = Some(error.to_string());
                            break;
                        }
                    }
                }
                outputs.finish(Ok(())).unwrap();
                let context = format!("{overwrite:?} threads={threads}");
                assert_eq!(listing(&root), ["x", "y"], "{context}");
                if overwrite == OverwritePolicy::Always {
                    assert_eq!(refused, None, "{context}");
                    assert_eq!(fs::read(root.join("x")).unwrap(), b"3", "{context}");
                } else {
                    let error = refused.expect("a repeat is refused under Rename");
                    assert!(error.contains("same output path"), "{context}: {error}");
                    assert_eq!(fs::read(root.join("x")).unwrap(), b"0", "{context}");
                }
            });
        }
    }
}

#[test]
fn staged_files_keep_their_times_unless_times_are_left_alone() {
    let modified = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_600_000_000);
    let timed = |name: &str| {
        crate::ExtractedEntryMeta::new(
            name.as_bytes().to_vec(),
            Some(crate::Timestamp::from_unix_seconds(1_600_000_000)),
            0,
            false,
        )
    };
    for threads in THREADS {
        capped(threads, || {
            for restore_times in [true, false] {
                let root = crate::scratch::case("dir-extraction-times");
                let mut written = mode(OverwritePolicy::Never);
                written.restore_times = restore_times;
                let mut outputs = outputs(&root, written);
                for name in ["d/one", "d/two", "three"] {
                    open_and_write(&mut outputs, &timed(name), name.as_bytes());
                }
                // Nothing writes it: it is created as it closes.
                drop(outputs.open(&timed("empty")).unwrap());
                outputs.settle(Settled::Verified).unwrap();
                outputs.finish(Ok(())).unwrap();
                for name in ["d/one", "d/two", "three", "empty"] {
                    let context = format!("threads={threads} {name}");
                    let published = fs::metadata(root.join(name)).expect(&context);
                    let restored = published.modified().unwrap() == modified;
                    assert_eq!(restored, restore_times, "{context}");
                }
                assert_eq!(fs::read(root.join("empty")).unwrap(), b"");
            }
        });
    }
}

#[cfg(any(target_vendor = "apple", target_os = "linux", target_os = "android"))]
fn plant_next_staged(outputs: &DirExtraction<'_>) {
    let engine = &outputs.engine;
    let (_, files) = engine
        .staging_files
        .as_ref()
        .expect("a member staged by descriptor already");
    fs::write(files.join(engine.staged_count.to_string()), b"planted").unwrap();
}

#[cfg(any(target_vendor = "apple", target_os = "linux", target_os = "android"))]
#[test]
fn a_staged_file_that_cant_be_created_fails_its_write_not_its_open() {
    for threads in THREADS {
        capped(threads, || {
            let root = crate::scratch::case("dir-extraction-staged-create-fails");
            let mut outputs = outputs(&root, mode(OverwritePolicy::Never));
            write(&mut outputs, &file("first"), b"first");
            plant_next_staged(&outputs);
            let mut writer = outputs
                .open(&file("second"))
                .expect("opening creates no file");
            // Written on another thread, as the decode workers do.
            let error = std::thread::spawn(move || writer.write_all(b"second"))
                .join()
                .unwrap()
                .unwrap_err();
            assert_eq!(
                error.kind(),
                io::ErrorKind::AlreadyExists,
                "threads={threads}"
            );
            outputs.settle(Settled::Verified).unwrap();
            outputs.settle(Settled::Failed).unwrap();
            outputs.finish(Ok(())).unwrap();
            assert_eq!(listing(&root), ["first"], "threads={threads}");
        });
    }
}

#[cfg(any(target_vendor = "apple", target_os = "linux", target_os = "android"))]
#[test]
fn an_empty_member_whose_staged_file_cant_be_created_fails_to_publish_saying_so() {
    for threads in THREADS {
        capped(threads, || {
            let root = crate::scratch::case("dir-extraction-empty-create-fails");
            let mut outputs = outputs(&root, mode(OverwritePolicy::Never));
            write(&mut outputs, &file("first"), b"first");
            plant_next_staged(&outputs);
            drop(outputs.open(&file("empty")).unwrap());
            outputs.settle(Settled::Verified).unwrap();
            let settled = outputs.settle(Settled::Verified);
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
fn modes_are_restored_on_files_links_and_directories() {
    use std::os::unix::fs::PermissionsExt;
    let unix = |name: &str, mode: u64, directory: bool| {
        crate::ExtractedEntryMeta::new(name.as_bytes().to_vec(), None, mode, directory)
            .with_attr_source(crate::AttrSource::Unix)
    };
    for threads in THREADS {
        capped(threads, || {
            for in_place in [false, true] {
                let root = crate::scratch::case("dir-extraction-modes");
                let mut moded = mode(OverwritePolicy::Never);
                moded.restore_modes = true;
                moded.in_place = in_place;
                let mut outputs = outputs(&root, moded);
                outputs.written_elsewhere(!in_place);
                let members = [
                    unix("d", 0o040700, true),
                    unix("d/604", 0o100604, false),
                    unix("777", 0o100777, false),
                    unix("600", 0o100600, false),
                    unix("200", 0o100200, false),
                ];
                for meta in &members {
                    open_and_write(&mut outputs, meta, b"x");
                }
                let links = [
                    // Its own mode would be its target's.
                    ("hard", 0o100644, ExtractedLink::HardLink { target: b"600" }),
                    ("copy", 0o100600, ExtractedLink::FileCopy { target: b"600" }),
                    (
                        "copy200",
                        0o100200,
                        ExtractedLink::FileCopy { target: b"200" },
                    ),
                ];
                for (name, mode, link) in links {
                    outputs.link(&unix(name, mode, false), link).unwrap();
                }
                outputs.finish(Ok(())).unwrap();
                for (name, mode) in [
                    ("d", 0o700),
                    ("d/604", 0o604),
                    ("777", 0o777),
                    ("600", 0o600),
                    ("200", 0o200),
                    ("hard", 0o600),
                    ("copy", 0o600),
                    ("copy200", 0o200),
                ] {
                    let found = fs::metadata(root.join(name)).unwrap().permissions().mode();
                    assert_eq!(found & 0o7777, mode, "{name} in_place={in_place}");
                }
            }
        });
    }
}

#[test]
fn writing_in_place_or_flattened_settles_each_member_before_the_next_opens() {
    for threads in THREADS {
        capped(threads, || {
            for (in_place, flatten) in [(true, false), (false, true)] {
                let case = format!("threads={threads} in_place={in_place} flatten={flatten}");
                let root = crate::scratch::case("dir-extraction-in-order");
                let mut written = mode(OverwritePolicy::Never);
                written.in_place = in_place;
                written.flatten = flatten;
                let mut outputs = outputs(&root, written);
                assert!(!outputs.can_open_ahead(), "{case}");
                drop(outputs.open(&dir("d")).unwrap());
                outputs.settle(Settled::Verified).unwrap();
                write(&mut outputs, &file("d/kept"), b"kept");
                outputs.settle(Settled::Verified).unwrap();
                write(&mut outputs, &file("d/broken"), b"broken");
                outputs.settle(Settled::Failed).unwrap();
                write(&mut outputs, &file("d/salvaged"), b"salvaged");
                outputs.settle(Settled::KeptBroken).unwrap();

                let extracted = outputs.finish(Ok(())).unwrap();

                let at = |name: &str| match flatten {
                    true => root.join(name),
                    false => root.join("d").join(name),
                };
                let mut expected: Vec<PathBuf> = vec![at("kept"), at("salvaged")];
                if !flatten {
                    expected.insert(0, root.join("d"));
                }
                assert_eq!(extracted.paths, expected, "{case}");
                assert_eq!(fs::read(at("kept")).unwrap(), b"kept", "{case}");
                assert_eq!(fs::read(at("salvaged")).unwrap(), b"salvaged", "{case}");
            }
        });
    }
}

#[test]
fn flattened_under_always_a_replaced_member_is_listed_once_where_it_last_landed() {
    let root = crate::scratch::case("dir-extraction-flat-listed-once");
    let mut flat = mode(OverwritePolicy::Always);
    flat.flatten = true;
    let mut outputs = outputs(&root, flat);
    for (name, bytes) in [("a/x", b"1"), ("y", b"2"), ("b/x", b"3")] {
        open_and_write(&mut outputs, &file(name), bytes);
    }
    let extracted = outputs.finish(Ok(())).unwrap();
    assert_eq!(extracted.paths, [root.join("y"), root.join("x")]);
    assert_eq!(fs::read(root.join("x")).unwrap(), b"3");
}

#[test]
fn a_link_leading_outside_is_listed_under_its_stored_name() {
    let root = crate::scratch::case("dir-extraction-skipped-link");
    let mut outputs = outputs(&root, mode(OverwritePolicy::Never));
    outputs
        .link(
            &file("out"),
            ExtractedLink::Symlink {
                target: b"../escape",
                directory: false,
            },
        )
        .unwrap();
    let extracted = outputs.finish(Ok(())).unwrap();
    assert_eq!(extracted.paths, [] as [PathBuf; 0]);
    assert_eq!(
        extracted.skipped_links,
        [SkippedLink {
            name: b"out".to_vec(),
            target: b"../escape".to_vec(),
        }]
    );
}

#[cfg(unix)]
#[test]
fn a_symlink_planted_in_a_directory_the_run_made_is_refused_as_one() {
    for overwrite in [
        OverwritePolicy::Never,
        OverwritePolicy::Always,
        OverwritePolicy::Rename,
    ] {
        for in_place in [false, true] {
            let case = format!("{overwrite:?} in_place={in_place}");
            let root = crate::scratch::case("dir-extraction-planted");
            let victim = root.with_extension("victim");
            fs::write(&victim, b"victim").unwrap();
            let mut planted = mode(overwrite);
            planted.in_place = in_place;
            let mut outputs = outputs(&root, planted);
            open_and_write(&mut outputs, &file("d/one"), b"one");
            // As a `volumes` iterator in Python can, once what is queued is in place.
            outputs.publish_waiter()();
            std::os::unix::fs::symlink(&victim, root.join("d/two")).unwrap();
            let error = match outputs.open(&file("d/two")) {
                Ok(_) => panic!("{case}: the member opened"),
                Err(error) => error,
            };
            outputs.settle(Settled::Failed).unwrap();
            outputs.finish(Ok(())).unwrap();
            assert_eq!(
                error.kind(),
                crate::ErrorKind::UnsafePath,
                "{case}: {error}"
            );
            assert_eq!(fs::read(&victim).unwrap(), b"victim", "{case}");
        }
    }
}

#[cfg(unix)]
#[test]
fn a_failed_run_still_restores_what_it_published() {
    use std::os::unix::fs::PermissionsExt;
    let modified = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_600_000_000);
    let unix = |name: &str, mode: u64, directory: bool| {
        crate::ExtractedEntryMeta::new(
            name.as_bytes().to_vec(),
            Some(crate::Timestamp::from_unix_seconds(1_600_000_000)),
            mode,
            directory,
        )
        .with_attr_source(crate::AttrSource::Unix)
    };
    for threads in THREADS {
        capped(threads, || {
            let root = crate::scratch::case("dir-extraction-failed-restores");
            let mut restored = mode(OverwritePolicy::Never);
            restored.restore_times = true;
            restored.restore_modes = true;
            let mut outputs = outputs(&root, restored);
            drop(outputs.open(&unix("d", 0o040700, true)).unwrap());
            outputs.settle(Settled::Verified).unwrap();
            // Its mode waits for the end: its owner can't read it.
            open_and_write(&mut outputs, &unix("d/locked", 0o100200, false), b"x");
            let error = outputs.finish(Err(crate::Error::InvalidHeader("later member")));
            assert!(error.is_err(), "threads={threads}");
            let directory = fs::metadata(root.join("d")).unwrap();
            assert_eq!(directory.modified().unwrap(), modified, "threads={threads}");
            assert_eq!(
                directory.permissions().mode() & 0o7777,
                0o700,
                "threads={threads}"
            );
            let locked = fs::metadata(root.join("d/locked")).unwrap();
            assert_eq!(
                locked.permissions().mode() & 0o7777,
                0o200,
                "threads={threads}"
            );
        });
    }
}

#[cfg(unix)]
#[test]
fn each_symlink_policy_makes_the_links_it_names() {
    let link = |target: &'static [u8]| ExtractedLink::Symlink {
        target,
        directory: false,
    };
    for policy in [
        crate::SymlinkPolicy::Inside,
        crate::SymlinkPolicy::All,
        crate::SymlinkPolicy::Skip,
    ] {
        for threads in THREADS {
            capped(threads, || {
                let case = format!("{policy:?} threads={threads}");
                let root = crate::scratch::case("dir-extraction-symlink-policy");
                let out = root.join("out");
                let mut linked = mode(OverwritePolicy::Never);
                linked.symlinks = policy;
                let mut outputs = outputs(&out, linked);
                open_and_write(&mut outputs, &file("file.txt"), b"file");
                outputs.link(&file("inside"), link(b"file.txt")).unwrap();
                outputs.link(&file("up"), link(b"../outside")).unwrap();
                outputs.link(&file("abs"), link(b"/absolute")).unwrap();
                let extracted = outputs.finish(Ok(())).unwrap();
                let made = |name: &str| fs::read_link(out.join(name)).ok();
                let skipped: Vec<_> = extracted
                    .skipped_links
                    .iter()
                    .map(|link| link.name.clone())
                    .collect();
                match policy {
                    crate::SymlinkPolicy::Inside => {
                        assert_eq!(made("inside"), Some("file.txt".into()), "{case}");
                        assert_eq!(made("up"), None, "{case}");
                        assert_eq!(made("abs"), None, "{case}");
                        assert_eq!(skipped, [b"up".to_vec(), b"abs".to_vec()], "{case}");
                    }
                    crate::SymlinkPolicy::All => {
                        assert_eq!(made("inside"), Some("file.txt".into()), "{case}");
                        assert_eq!(made("up"), Some("../outside".into()), "{case}");
                        assert_eq!(made("abs"), Some("/absolute".into()), "{case}");
                        assert!(skipped.is_empty(), "{case}");
                    }
                    _ => {
                        assert_eq!(listing(&out), ["file.txt"], "{case}");
                        assert!(skipped.is_empty(), "{case}");
                    }
                }
            });
        }
    }
}

#[cfg(unix)]
#[test]
fn a_member_under_a_link_the_run_made_replaces_it_with_a_directory() {
    for (policy, target) in [
        (crate::SymlinkPolicy::Inside, b"real".as_slice()),
        (crate::SymlinkPolicy::All, b"../victim"),
    ] {
        for in_place in [false, true] {
            for threads in THREADS {
                capped(threads, || {
                    let case = format!("{policy:?} in_place={in_place} threads={threads}");
                    let root = crate::scratch::case("dir-extraction-under-made-link");
                    let out = root.join("out");
                    fs::create_dir_all(root.join("victim")).unwrap();
                    let mut linked = mode(OverwritePolicy::Never);
                    linked.symlinks = policy;
                    linked.in_place = in_place;
                    let mut outputs = outputs(&out, linked);
                    outputs.written_elsewhere(!in_place);
                    drop(outputs.open(&dir("real")).unwrap());
                    outputs.settle(Settled::Verified).unwrap();
                    let link = ExtractedLink::Symlink {
                        target,
                        directory: true,
                    };
                    outputs.link(&file("link"), link).unwrap();
                    open_and_write(&mut outputs, &file("link/file.txt"), b"under");
                    outputs.finish(Ok(())).unwrap();
                    let at = out.join("link");
                    assert!(
                        fs::symlink_metadata(&at).unwrap().is_dir(),
                        "{case}: the link gave way to a directory"
                    );
                    assert_eq!(fs::read(at.join("file.txt")).unwrap(), b"under", "{case}");
                    assert_eq!(listing(&out.join("real")), [] as [&str; 0], "{case}");
                    assert_eq!(listing(&root.join("victim")), [] as [&str; 0], "{case}");
                });
            }
        }
    }
}

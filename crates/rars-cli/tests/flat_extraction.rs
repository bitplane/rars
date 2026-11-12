#[path = "support/scratch.rs"]
mod scratch;
use rars::{ArchiveVersion, Builder};
use std::{
    fs,
    path::Path,
    process::{Command, Output},
};

const VERSIONS: [ArchiveVersion; 3] = [
    ArchiveVersion::Rar14,
    ArchiveVersion::Rar29,
    ArchiveVersion::Rar50,
];

fn extract(archive: &Path, out: &Path, extra: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rars"))
        .arg("extract")
        .args(extra)
        .arg(archive)
        .arg(out)
        .output()
        .unwrap()
}

fn write_archive(path: &Path, version: ArchiveVersion, files: &[(&str, &str)]) {
    let mut builder = Builder::new(version);
    builder.add_directory(b"a".to_vec(), None, None).unwrap();
    for (name, contents) in files {
        builder
            .add_bytes(
                name.as_bytes().to_vec(),
                contents.as_bytes().to_vec(),
                None,
                None,
            )
            .unwrap();
    }
    fs::write(path, builder.to_bytes().unwrap()).unwrap();
}

fn listing(out: &Path) -> Vec<(String, String)> {
    let mut entries: Vec<_> = fs::read_dir(out)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            assert!(entry.file_type().unwrap().is_file(), "{:?}", entry.path());
            (
                entry.file_name().into_string().unwrap(),
                fs::read_to_string(entry.path()).unwrap(),
            )
        })
        .collect();
    entries.sort();
    entries
}

fn owned(entries: &[(&str, &str)]) -> Vec<(String, String)> {
    entries
        .iter()
        .map(|(name, contents)| (name.to_string(), contents.to_string()))
        .collect()
}

fn succeeded(result: &Output) -> String {
    let stderr = String::from_utf8_lossy(&result.stderr).into_owned();
    assert!(result.status.success(), "{stderr}");
    String::from_utf8_lossy(&result.stdout).into_owned()
}

#[test]
fn flatten_writes_every_file_into_the_output_directory() {
    for version in VERSIONS {
        let root = scratch::case("flat-nested");
        let archive = root.join("nested.rar");
        write_archive(
            &archive,
            version,
            &[("a/one.txt", "1"), ("a/b/two.txt", "2"), ("top.txt", "3")],
        );
        let out = root.join("out");
        succeeded(&extract(&archive, &out, &["--flatten"]));
        assert_eq!(
            listing(&out),
            owned(&[("one.txt", "1"), ("top.txt", "3"), ("two.txt", "2")]),
            "{version:?}"
        );
        let nested = root.join("nested");
        succeeded(&extract(&archive, &nested, &[]));
        assert_eq!(fs::read_to_string(nested.join("a/b/two.txt")).unwrap(), "2");
    }
}

fn collide(version: ArchiveVersion, old: bool, extra: &[&str]) -> (Output, Vec<(String, String)>) {
    let root = scratch::case("flat-collide");
    let archive = root.join("collide.rar");
    write_archive(
        &archive,
        version,
        &[("a/readme.txt", "first"), ("b/readme.txt", "second")],
    );
    let out = root.join("out");
    fs::create_dir(&out).unwrap();
    if old {
        fs::write(out.join("readme.txt"), "old").unwrap();
    }
    let result = extract(&archive, &out, &[&["--flatten"], extra].concat());
    let entries = listing(&out)
        .into_iter()
        .filter(|(name, _)| !name.starts_with(".rars-extract"))
        .collect();
    (result, entries)
}

#[test]
fn flat_collisions_follow_the_overwrite_setting() {
    for version in VERSIONS {
        let (result, entries) = collide(version, false, &[]);
        let stderr = String::from_utf8_lossy(&result.stderr);
        assert!(!result.status.success());
        assert!(
            stderr.contains("a/readme.txt") && stderr.contains("b/readme.txt"),
            "{stderr}"
        );
        assert_eq!(entries, owned(&[("readme.txt", "first")]), "{version:?}");

        let (result, entries) = collide(version, false, &["--overwrite=always"]);
        succeeded(&result);
        assert_eq!(entries, owned(&[("readme.txt", "second")]), "{version:?}");
        let (result, entries) = collide(version, true, &["--overwrite=always"]);
        succeeded(&result);
        assert_eq!(entries, owned(&[("readme.txt", "second")]), "{version:?}");

        let (result, entries) = collide(version, false, &["--overwrite=rename"]);
        let stdout = succeeded(&result);
        assert!(stdout.contains("b/readme.txt -> readme(1).txt"), "{stdout}");
        assert_eq!(
            entries,
            owned(&[("readme(1).txt", "second"), ("readme.txt", "first")]),
            "{version:?}"
        );
        for in_place in [&[][..], &["--in-place"]] {
            let (result, entries) =
                collide(version, true, &[&["--overwrite=rename"], in_place].concat());
            succeeded(&result);
            assert_eq!(
                entries,
                owned(&[
                    ("readme(1).txt", "first"),
                    ("readme(2).txt", "second"),
                    ("readme.txt", "old")
                ]),
                "{version:?} {in_place:?}"
            );
        }
    }
}

#[test]
fn rename_without_flatten_renames_only_against_files_on_disk() {
    for version in VERSIONS {
        let root = scratch::case("rename-nested");
        let archive = root.join("collide.rar");
        write_archive(
            &archive,
            version,
            &[("a/readme.txt", "first"), ("b/readme.txt", "second")],
        );
        let out = root.join("out");
        fs::create_dir_all(out.join("a")).unwrap();
        fs::write(out.join("a/readme.txt"), "old").unwrap();
        succeeded(&extract(&archive, &out, &["--overwrite=rename"]));
        assert_eq!(
            listing(&out.join("a")),
            owned(&[("readme(1).txt", "first"), ("readme.txt", "old")]),
            "{version:?}"
        );
        assert_eq!(
            listing(&out.join("b")),
            owned(&[("readme.txt", "second")]),
            "{version:?}"
        );
    }
}

fn fixture(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../rars/tests/fixtures/rar50")
        .join(name)
}

#[cfg(unix)]
fn link_listing(out: &Path) -> Vec<(String, String)> {
    let mut entries: Vec<_> = fs::read_dir(out)
        .unwrap()
        .map(|entry| {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_str().unwrap().to_owned();
            let kind = match fs::read_link(&path) {
                Ok(target) => format!("-> {}", target.display()),
                Err(_) => fs::read_to_string(&path).unwrap(),
            };
            (name, kind)
        })
        .collect();
    entries.sort();
    entries
}

#[cfg(unix)]
#[test]
fn flat_links_resolve_to_flattened_targets_and_skip_any_with_a_path() {
    use std::os::unix::fs::MetadataExt;
    let root = scratch::case("flat-links");
    let out = root.join("out");
    let result = extract(&fixture("flat_links.rar"), &out, &["--flatten"]);
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert_eq!(result.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains("a/sym.txt") && stderr.contains("a/abs.txt"),
        "{stderr}"
    );
    assert_eq!(
        link_listing(&out),
        owned(&[
            ("copy.txt", "target\n"),
            ("hard.txt", "target\n"),
            ("local.txt", "local\n"),
            ("near.txt", "-> local.txt"),
            ("target.txt", "target\n"),
        ])
    );
    let target = fs::metadata(out.join("target.txt")).unwrap();
    let hard = fs::metadata(out.join("hard.txt")).unwrap();
    assert_eq!((hard.ino(), hard.nlink()), (target.ino(), 2));
    assert_ne!(
        fs::metadata(out.join("copy.txt")).unwrap().ino(),
        target.ino()
    );

    let unrar = Command::new("unrar")
        .args(["e", "-idq", "-o+"])
        .arg(fixture("flat_links.rar"))
        .arg(format!("{}/", root.join("unrar").display()))
        .output();
    match unrar {
        Ok(output) => {
            assert_eq!(output.status.code(), Some(1));
            assert_eq!(link_listing(&root.join("unrar")), link_listing(&out));
        }
        Err(_) => eprintln!("unrar not installed; skipped the comparison"),
    }
}

#[cfg(unix)]
#[test]
fn flat_links_take_the_renamed_target_name() {
    use std::os::unix::fs::MetadataExt;
    let root = scratch::case("flat-links-renamed");
    let out = root.join("out");
    fs::create_dir(&out).unwrap();
    fs::write(out.join("target.txt"), "old").unwrap();
    let result = extract(
        &fixture("flat_links.rar"),
        &out,
        &["--flatten", "--overwrite=rename"],
    );
    assert_eq!(result.status.code(), Some(1));
    let target = fs::metadata(out.join("target(1).txt")).unwrap();
    let hard = fs::metadata(out.join("hard.txt")).unwrap();
    assert_eq!((hard.ino(), hard.nlink()), (target.ino(), 2));
    assert_eq!(
        fs::read_to_string(out.join("copy.txt")).unwrap(),
        "target\n"
    );
    assert_eq!(fs::read_to_string(out.join("target.txt")).unwrap(), "old");
}

#[cfg(unix)]
#[test]
fn flat_legacy_symlinks_keep_only_bare_targets() {
    for version in [ArchiveVersion::Rar29, ArchiveVersion::Rar50] {
        let root = scratch::case("flat-legacy-links");
        let archive = root.join("links.rar");
        let mut builder = Builder::new(version);
        builder
            .add_bytes(b"a/local.txt".to_vec(), b"local".to_vec(), None, None)
            .unwrap();
        for (name, target) in [("a/near.txt", "local.txt"), ("a/up.txt", "../x/local.txt")] {
            builder
                .add_unix_symlink(name.into(), target.into(), false, None, None)
                .unwrap();
        }
        fs::write(&archive, builder.to_bytes().unwrap()).unwrap();
        let out = root.join("out");
        let result = extract(&archive, &out, &["--flatten"]);
        let stderr = String::from_utf8_lossy(&result.stderr);
        assert_eq!(result.status.code(), Some(1), "{version:?} {stderr}");
        assert!(stderr.contains("a/up.txt"), "{stderr}");
        assert_eq!(
            link_listing(&out),
            owned(&[("local.txt", "local"), ("near.txt", "-> local.txt")]),
            "{version:?}"
        );
    }
}

#[test]
fn flatten_cannot_escape_the_output_directory() {
    use rars::rar13::{write_stored_archive, StoredEntry, WriterOptions};
    for name in [
        &b"../evil.txt"[..],
        b"a/../../evil.txt",
        b"/abs/evil.txt",
        b"C:evil.txt",
        b"..",
    ] {
        for overwrite in ["never", "always", "rename"] {
            let root = scratch::case("flat-hostile");
            let archive = root.join("hostile.rar");
            let entry = StoredEntry {
                name,
                data: b"evil",
                file_time: 0,
                file_attr: 0x20,
                password: None,
                file_comment: None,
            };
            fs::write(
                &archive,
                write_stored_archive(&[entry], WriterOptions::default()).unwrap(),
            )
            .unwrap();
            let out = root.join("deep/out");
            let overwrite = format!("--overwrite={overwrite}");
            let result = extract(&archive, &out, &["--flatten", &overwrite]);
            assert!(!result.status.success(), "{name:?} {overwrite}");
            for escaped in ["deep/evil.txt", "evil.txt", "deep/out/evil.txt"] {
                assert!(
                    !root.join(escaped).exists(),
                    "{name:?} {overwrite} {escaped}"
                );
            }
        }
    }
}

#[test]
fn flatten_reaches_across_a_volume_set_found_by_name() {
    for version in [ArchiveVersion::Rar29, ArchiveVersion::Rar50] {
        let root = scratch::case("flat-volumes");
        let mut builder = Builder::new(version).store(true).volume_size(Some(4096));
        // Legacy volume sets hold one input.
        let members: &[(&str, u8)] = if version == ArchiveVersion::Rar50 {
            &[("a/one.bin", 1), ("b/c/two.bin", 2)]
        } else {
            &[("b/c/two.bin", 2)]
        };
        let payload = |byte: u8| vec![byte; if members.len() == 1 { 9000 } else { 3000 }];
        for &(name, byte) in members {
            builder
                .add_bytes(name.as_bytes().to_vec(), payload(byte), None, None)
                .unwrap();
        }
        let volumes = builder.build_volumes(None).unwrap();
        assert!(volumes.len() > 1);
        let first = root.join("set.part1.rar");
        for (index, volume) in volumes.iter().enumerate() {
            let path = if version == ArchiveVersion::Rar50 {
                root.join(format!("set.part{}.rar", index + 1))
            } else if index == 0 {
                root.join("set.rar")
            } else {
                root.join(format!("set.r{:02}", index - 1))
            };
            fs::write(path, volume).unwrap();
        }
        let first = if version == ArchiveVersion::Rar50 {
            first
        } else {
            root.join("set.rar")
        };
        let out = root.join("out");
        succeeded(&extract(&first, &out, &["--flatten"]));
        let mut names: Vec<_> = fs::read_dir(&out)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        let expected: Vec<_> = members
            .iter()
            .map(|(name, _)| name.rsplit('/').next().unwrap())
            .collect();
        assert_eq!(names, expected, "{version:?}");
        assert_eq!(fs::read(out.join("two.bin")).unwrap(), payload(2));
    }
}

#[test]
fn member_times_are_restored_on_flattened_and_renamed_files() {
    for version in VERSIONS {
        let root = scratch::case("flat-times");
        let archive = root.join("times.rar");
        let mut builder = Builder::new(version);
        // Legacy formats take DOS-packed times.
        let times = if version == ArchiveVersion::Rar50 {
            [1_600_000_000, 1_700_000_000]
        } else {
            [0x5A21_6000, 0x5E21_6000]
        };
        for (name, time) in [("a/readme.txt", times[0]), ("b/readme.txt", times[1])] {
            builder
                .add_bytes(name.as_bytes().to_vec(), b"x".to_vec(), Some(time), None)
                .unwrap();
        }
        fs::write(&archive, builder.to_bytes().unwrap()).unwrap();
        let out = root.join("out");
        succeeded(&extract(
            &archive,
            &out,
            &["--flatten", "--overwrite=rename"],
        ));
        let nested = root.join("nested");
        succeeded(&extract(&archive, &nested, &[]));
        let modified = |path: &Path| fs::metadata(path).unwrap().modified().unwrap();
        assert_ne!(
            modified(&nested.join("a/readme.txt")),
            modified(&nested.join("b/readme.txt"))
        );
        for (flat, stored) in [
            ("readme.txt", "a/readme.txt"),
            ("readme(1).txt", "b/readme.txt"),
        ] {
            assert_eq!(
                modified(&out.join(flat)),
                modified(&nested.join(stored)),
                "{version:?} {flat}"
            );
        }
    }
}

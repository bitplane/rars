//! `unrars` as callers run it: the commands, output lines and exit codes they rely on.

#[path = "support/scratch.rs"]
mod scratch;
use rars::{ArchiveVersion, Builder};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn unrars(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_unrars"))
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn builder(password: Option<&[u8]>) -> Builder {
    let mut builder = Builder::new(ArchiveVersion::Rar50)
        .store(true)
        .password(password.map(<[u8]>::to_vec));
    builder
        .add_bytes(b"a.txt".to_vec(), b"hello\n".to_vec(), None, None)
        .unwrap();
    builder.add_directory(b"sub".to_vec(), None, None).unwrap();
    builder
        .add_bytes(b"sub/b.bin".to_vec(), payload(), None, None)
        .unwrap();
    builder
}

fn payload() -> Vec<u8> {
    (0..20_000u32).map(|n| (n * 7 % 251) as u8).collect()
}

fn write(dir: &Path, name: &str, password: Option<&[u8]>) -> PathBuf {
    let path = dir.join(name);
    builder(password).write_to_path(&path, None).unwrap();
    path
}

#[test]
fn extracts_with_the_lines_callers_parse() {
    let dir = scratch::case("unrars-extract");
    write(&dir, "plain.rar", None);
    let output = unrars(&dir, &["x", "-idp", "-o+", "-p-", "plain.rar", "out/"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let text = stdout(&output);
    assert!(text.contains("Extracting from plain.rar"), "{text}");
    // The destination as given, then the member's path with native separators.
    let extracted = format!(
        "Extracting  {}",
        Path::new("out/").join("sub").join("b.bin").display()
    );
    assert!(
        text.lines()
            .any(|line| line.starts_with(&extracted) && line.ends_with("OK")),
        "{text}"
    );
    assert!(text.contains("Creating    out/sub"), "{text}");
    assert!(text.trim_end().ends_with("All OK"), "{text}");
    assert!(!text.contains("Roshal"));
    assert_eq!(fs::read(dir.join("out/sub/b.bin")).unwrap(), payload());
}

/// An archive cut inside its recovery record, after its last member.
fn write_cut_in_recovery_record(dir: &Path, name: &str) -> PathBuf {
    let path = dir.join(name);
    builder(None)
        .recovery_percent(Some(10))
        .write_to_path(&path, None)
        .unwrap();
    let archive = rars::rar50::Archive::parse_path(&path).unwrap();
    let recovery = archive.services().find(|service| service.name == b"RR");
    let cut = recovery.unwrap().block.data_range.start + 100;
    let bytes = fs::read(&path).unwrap();
    fs::write(&path, &bytes[..cut]).unwrap();
    path
}

#[test]
fn a_truncated_archive_is_a_warning_after_every_member() {
    let dir = scratch::case("unrars-truncated");
    write_cut_in_recovery_record(&dir, "cut.rar");
    for args in [
        &["t", "cut.rar"][..],
        &["x", "-o+", "cut.rar", "out/"],
        &["l", "cut.rar"],
        &["lb", "cut.rar"],
    ] {
        let output = unrars(&dir, args);
        assert_eq!(
            output.status.code(),
            Some(1),
            "{args:?}: {}",
            stderr(&output)
        );
        let errors = stderr(&output);
        assert!(
            errors.contains("Unexpected end of archive"),
            "{args:?}: {errors}"
        );
        assert!(
            errors.contains("Truncated at the service block: recovery record"),
            "{args:?}: {errors}"
        );
        let text = stdout(&output);
        assert!(!text.contains("All OK"), "{args:?}: {text}");
        if args[0] == "t" {
            assert!(text.contains("Total errors: 1"), "{text}");
            assert!(text
                .lines()
                .any(|line| line.contains("b.bin") && line.ends_with("OK")));
        }
    }
    assert_eq!(fs::read(dir.join("out/sub/b.bin")).unwrap(), payload());
}

/// Issue #489: like unrar, nothing to say about a file that stops at its end
/// block, when the recovery record before it shows no member can be missing.
/// Where a member could be, the cut is still reported.
#[test]
fn a_file_stopping_at_its_end_block_after_every_member_tests_clean() {
    let dir = scratch::case("unrars-end-block");
    let path = dir.join("cut.rar");
    builder(None)
        .recovery_percent(Some(10))
        .write_to_path(&path, None)
        .unwrap();
    let bytes = fs::read(&path).unwrap();
    // RAR 5's end block is eight bytes here: CRC, size, type, flags and end flags.
    fs::write(&path, &bytes[..bytes.len() - 8]).unwrap();
    let output = unrars(&dir, &["t", "cut.rar"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(stderr(&output).is_empty(), "{}", stderr(&output));
    assert!(stdout(&output).trim_end().ends_with("All OK"));

    let plain = dir.join("plain.rar");
    builder(None).write_to_path(&plain, None).unwrap();
    let bytes = fs::read(&plain).unwrap();
    fs::write(&plain, &bytes[..bytes.len() - 8]).unwrap();
    let output = unrars(&dir, &["t", "plain.rar"]);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(stderr(&output).contains("Unexpected end of archive"));
}

#[test]
fn keeps_or_replaces_existing_files() {
    let dir = scratch::case("unrars-overwrite");
    write(&dir, "plain.rar", None);
    fs::create_dir(dir.join("out")).unwrap();
    fs::write(dir.join("out/a.txt"), b"mine").unwrap();
    // Once every file is there, keeping them all writes nothing, which unrar reports as no files.
    for (keep, code) in [(&["-o-"][..], 0), (&[][..], 10)] {
        let mut args = vec!["x", "-idq"];
        args.extend(keep);
        args.extend(["plain.rar", "out/"]);
        assert_eq!(unrars(&dir, &args).status.code(), Some(code));
        assert_eq!(fs::read(dir.join("out/a.txt")).unwrap(), b"mine");
    }
    let output = unrars(&dir, &["x", "-idq", "-y", "plain.rar", "out/"]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(fs::read(dir.join("out/a.txt")).unwrap(), b"hello\n");
}

#[test]
fn e_drops_paths_and_or_renames_beside_existing_files() {
    let dir = scratch::case("unrars-flat");
    write(&dir, "plain.rar", None);
    let output = unrars(&dir, &["e", "-idq", "plain.rar", "out/"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(fs::read(dir.join("out/b.bin")).unwrap(), payload());
    assert!(!dir.join("out/sub").exists());

    let output = unrars(&dir, &["e", "-idq", "-or", "plain.rar", "out/"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(fs::read(dir.join("out/b(1).bin")).unwrap(), payload());
    assert_eq!(fs::read(dir.join("out/a(1).txt")).unwrap(), b"hello\n");

    // Two members on one flat name: -o- keeps the first, -o+ the last, -or both.
    let mut repeated = Builder::new(ArchiveVersion::Rar50).store(true);
    for (name, data) in [("a/readme.txt", "first"), ("b/readme.txt", "second")] {
        repeated
            .add_bytes(
                name.as_bytes().to_vec(),
                data.as_bytes().to_vec(),
                None,
                None,
            )
            .unwrap();
    }
    repeated
        .write_to_path(&dir.join("repeated.rar"), None)
        .unwrap();
    for (switch, out, files) in [
        ("-o-", "keep", &[("readme.txt", "first")][..]),
        ("-o+", "over", &[("readme.txt", "second")]),
        (
            "-or",
            "both",
            &[("readme.txt", "first"), ("readme(1).txt", "second")],
        ),
    ] {
        let output = unrars(
            &dir,
            &["e", "-idq", switch, "repeated.rar", &format!("{out}/")],
        );
        assert_eq!(
            output.status.code(),
            Some(0),
            "{switch} {}",
            stderr(&output)
        );
        for (name, data) in files {
            assert_eq!(fs::read_to_string(dir.join(out).join(name)).unwrap(), *data);
        }
    }
    let output = unrars(&dir, &["e", "-idq", "-o-", "repeated.rar", "keep/"]);
    assert_eq!(output.status.code(), Some(10), "{}", stderr(&output));
}

#[test]
fn prints_a_member_to_stdout_as_rarfile_asks() {
    let dir = scratch::case("unrars-print");
    write(&dir, "plain.rar", None);
    let check = unrars(&dir, &["-inul", "-?"]);
    assert_eq!(check.status.code(), Some(0));
    assert!(check.stdout.is_empty() || stdout(&check).contains("Usage"));
    let output = unrars(&dir, &["p", "-inul", "-p-", "--", "plain.rar", "sub/b.bin"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(output.stdout, payload());
}

#[test]
fn reads_later_volumes_and_names_a_missing_one() {
    let dir = scratch::case("unrars-volumes");
    let volumes = builder(None)
        .volume_size(Some(8 * 1024))
        .build_volumes(None)
        .unwrap();
    assert!(volumes.len() >= 3);
    for (index, bytes) in volumes.iter().enumerate() {
        fs::write(dir.join(format!("set.part{}.rar", index + 1)), bytes).unwrap();
    }
    let output = unrars(&dir, &["x", "-idp", "-o+", "-p-", "set.part1.rar", "out/"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let text = stdout(&output);
    assert!(text.contains("Extracting from set.part2.rar"), "{text}");
    assert_eq!(fs::read(dir.join("out/sub/b.bin")).unwrap(), payload());

    let last = format!("set.part{}.rar", volumes.len());
    fs::remove_file(dir.join(&last)).unwrap();
    let output = unrars(
        &dir,
        &["x", "-idp", "-o+", "-p-", "set.part1.rar", "again/"],
    );
    assert_eq!(output.status.code(), Some(6));
    assert!(
        stderr(&output).contains(&format!("Cannot find volume {last}")),
        "{}",
        stderr(&output)
    );
}

#[test]
fn reports_damage_passwords_and_non_archives() {
    let dir = scratch::case("unrars-failures");
    let path = write(&dir, "bad.rar", None);
    let mut bytes = fs::read(&path).unwrap();
    let at = bytes
        .windows(64)
        .position(|window| window == &payload()[1000..1064])
        .unwrap();
    bytes[at] ^= 0xff;
    fs::write(&path, bytes).unwrap();
    let output = unrars(&dir, &["t", "-idq", "bad.rar"]);
    assert_eq!(output.status.code(), Some(3));
    assert!(stderr(&output).contains("sub/b.bin"), "{}", stderr(&output));
    assert!(stderr(&output).contains("- checksum error"));

    write(&dir, "enc.rar", Some(b"secret"));
    let output = unrars(&dir, &["x", "-idq", "-pwrong", "enc.rar", "out/"]);
    assert_eq!(output.status.code(), Some(11));
    assert!(stderr(&output).contains("Incorrect password"));
    let output = unrars(&dir, &["x", "-idq", "-psecret", "enc.rar", "out/"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(fs::read(dir.join("out/a.txt")).unwrap(), b"hello\n");

    fs::write(dir.join("junk.rar"), b"not an archive").unwrap();
    let output = unrars(&dir, &["x", "-idp", "junk.rar", "out/"]);
    assert_eq!(output.status.code(), Some(10));
    assert!(stderr(&output).contains("junk.rar is not RAR archive"));
    assert_eq!(unrars(&dir, &["q", "junk.rar"]).status.code(), Some(7));
}

/// Three stored members, the middle one [`payload`].
fn write_three(path: &Path, version: ArchiveVersion) {
    let mut builder = Builder::new(version).store(true);
    for (name, data) in [
        (&b"a.txt"[..], b"hello\n".to_vec()),
        (b"mid.bin", payload()),
        (b"z.txt", b"after\n".to_vec()),
    ] {
        builder.add_bytes(name.to_vec(), data, None, None).unwrap();
    }
    builder.write_to_path(path, None).unwrap();
}

/// Issue #365: `-kb` keeps a member that fails its checksum with every byte
/// read for it, says so as unrar does after the file's line, goes on to the
/// members after it and exits with unrar's checksum status. Without `-kb`
/// nothing of it is kept.
#[test]
fn kb_keeps_a_member_that_fails_its_checksum() {
    let dir = scratch::case("unrars-kb-checksum");
    for version in [ArchiveVersion::Rar29, ArchiveVersion::Rar50] {
        let name = format!("{version:?}.rar");
        let path = dir.join(&name);
        write_three(&path, version);
        let mut bytes = fs::read(&path).unwrap();
        let start = bytes
            .windows(64)
            .position(|window| window == &payload()[..64])
            .unwrap();
        bytes[start + 1000] ^= 0xff;
        fs::write(&path, bytes).unwrap();
        let mut damaged = payload();
        damaged[1000] ^= 0xff;

        let out = format!("kb-{version:?}/");
        let output = unrars(&dir, &["x", "-kb", &name, &out]);
        let errors = stderr(&output);
        assert_eq!(output.status.code(), Some(3), "{version:?}: {errors}");
        assert!(
            errors.contains(&format!("{:<20} - checksum error", "mid.bin")),
            "{version:?}: {errors}"
        );
        let text = stdout(&output);
        assert!(text.contains("Total errors: 1"), "{version:?}: {text}");
        let kept_line = format!(
            "Extracting  {}\n",
            Path::new(&out).join("mid.bin").display()
        );
        assert!(text.contains(&kept_line), "{version:?}: {text}");
        assert!(fs::read(dir.join(&out).join("mid.bin")).unwrap() == damaged);
        assert_eq!(fs::read(dir.join(&out).join("a.txt")).unwrap(), b"hello\n");
        assert_eq!(fs::read(dir.join(&out).join("z.txt")).unwrap(), b"after\n");

        let out = format!("plain-{version:?}/");
        let output = unrars(&dir, &["x", &name, &out]);
        assert_eq!(output.status.code(), Some(3), "{version:?}");
        assert!(stderr(&output).contains("- checksum error"));
        assert!(!dir.join(&out).join("mid.bin").exists(), "{version:?}");
    }
}

/// Issue #365: `-kb` reads past a file header whose checksum fails, reports
/// it as unrar does and extracts its member and the ones after it.
#[test]
fn kb_reads_past_a_damaged_file_header() {
    let dir = scratch::case("unrars-kb-header");
    for version in [ArchiveVersion::Rar29, ArchiveVersion::Rar50] {
        let name = format!("{version:?}.rar");
        let path = dir.join(&name);
        write_three(&path, version);
        let mut bytes = fs::read(&path).unwrap();
        let at = bytes.windows(7).position(|v| v == b"mid.bin").unwrap();
        // Renames it to lid.bin, so the header fails its checksum.
        bytes[at] ^= 0x01;
        fs::write(&path, bytes).unwrap();

        let out = format!("kb-{version:?}/");
        let output = unrars(&dir, &["x", "-kb", &name, &out]);
        let errors = stderr(&output);
        assert_eq!(output.status.code(), Some(3), "{version:?}: {errors}");
        assert!(
            errors.contains("lid.bin - the file header is corrupt"),
            "{version:?}: {errors}"
        );
        assert_eq!(
            errors.contains("Corrupt header is found"),
            version == ArchiveVersion::Rar50,
            "{version:?}: {errors}"
        );
        assert!(stdout(&output).contains("Total errors: 2"), "{version:?}");
        assert_eq!(fs::read(dir.join(&out).join("lid.bin")).unwrap(), payload());
        assert_eq!(fs::read(dir.join(&out).join("z.txt")).unwrap(), b"after\n");
    }
}

#[test]
fn selects_members_by_mask_and_lists_bare_names() {
    let dir = scratch::case("unrars-masks");
    write(&dir, "plain.rar", None);
    let output = unrars(&dir, &["x", "-idq", "plain.rar", "*.txt", "out/"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(dir.join("out/a.txt").exists());
    assert!(!dir.join("out/sub/b.bin").exists());
    let output = unrars(&dir, &["x", "-idp", "plain.rar", "nothing.txt", "none/"]);
    assert_eq!(output.status.code(), Some(10));
    assert!(stdout(&output).contains("No files to extract"));
    let output = unrars(&dir, &["lb", "plain"]);
    assert_eq!(stdout(&output), "a.txt\nsub\nsub/b.bin\n");
}

/// Issue #564: the last word names the destination when it is a directory
/// that is already there, trailing separator or not.
#[test]
fn an_existing_directory_is_the_destination_without_a_separator() {
    let dir = scratch::case("unrars-destination-dir");
    write(&dir, "plain.rar", None);
    fs::create_dir(dir.join("out")).unwrap();
    let output = unrars(&dir, &["x", "-idq", "plain.rar", "out"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(fs::read(dir.join("out/a.txt")).unwrap(), b"hello\n");
    assert_eq!(fs::read(dir.join("out/sub/b.bin")).unwrap(), payload());
    // A word that names no directory is still a mask.
    let output = unrars(&dir, &["x", "-idq", "plain.rar", "elsewhere"]);
    assert_eq!(output.status.code(), Some(10), "{}", stderr(&output));
    assert!(!dir.join("elsewhere").exists());
}

/// Issue #564: `*` and `?` in the archive's name are expanded, and a volume
/// set they match is read once, from its first volume.
#[test]
fn expands_wildcards_in_the_archive_name() {
    let dir = scratch::case("unrars-archive-wildcards");
    for (name, member) in [("one.rar", "first.txt"), ("two.rar", "second.txt")] {
        let mut builder = Builder::new(ArchiveVersion::Rar50).store(true);
        builder
            .add_bytes(
                member.as_bytes().to_vec(),
                name.as_bytes().to_vec(),
                None,
                None,
            )
            .unwrap();
        builder.write_to_path(&dir.join(name), None).unwrap();
    }
    let volumes = builder(None)
        .volume_size(Some(8 * 1024))
        .build_volumes(None)
        .unwrap();
    assert!(volumes.len() >= 3);
    for (index, bytes) in volumes.iter().enumerate() {
        fs::write(dir.join(format!("set.part{}.rar", index + 1)), bytes).unwrap();
    }
    let output = unrars(&dir, &["x", "-o+", "-p-", "*.rar", "out/"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let text = stdout(&output);
    for name in ["one.rar", "two.rar", "set.part1.rar", "set.part2.rar"] {
        let line = format!("Extracting from {name}\n");
        assert_eq!(text.matches(&line).count(), 1, "{name}: {text}");
    }
    assert_eq!(text.matches("All OK").count(), 1, "{text}");
    assert_eq!(fs::read(dir.join("out/first.txt")).unwrap(), b"one.rar");
    assert_eq!(fs::read(dir.join("out/second.txt")).unwrap(), b"two.rar");
    assert_eq!(fs::read(dir.join("out/sub/b.bin")).unwrap(), payload());

    let output = unrars(&dir, &["x", "-idq", "o?e.rar", "single/"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(dir.join("single/first.txt").exists());
    assert!(!dir.join("single/second.txt").exists());

    let output = unrars(&dir, &["x", "none*.rar", "none/"]);
    assert_eq!(output.status.code(), Some(10), "{}", stderr(&output));
    assert!(stdout(&output).contains("No files to extract"));
}

/// An archive whose `a.txt` needs a password and whose `info.nfo` doesn't.
fn write_mixed(path: &Path) {
    let mut builder = Builder::new(ArchiveVersion::Rar50).store(true);
    builder
        .add_bytes(b"a.txt".to_vec(), b"secret text\n".to_vec(), None, None)
        .unwrap();
    builder
        .add_bytes(b"info.nfo".to_vec(), b"info\n".to_vec(), None, None)
        .unwrap();
    builder
        .set_entry_encryption(b"a.txt", Some(b"secret".to_vec()), None)
        .unwrap();
    builder.write_to_path(path, None).unwrap();
}

/// Issue #564: a member that needs a password no one gave, or gets the
/// wrong one, is reported by name and the run goes on to the next. One the
/// command line doesn't ask for is passed over without a word.
#[test]
fn a_member_with_the_wrong_password_does_not_stop_the_run() {
    let dir = scratch::case("unrars-mixed-password");
    write_mixed(&dir.join("mixed.rar"));
    for (password, out) in [("-p-", "none/"), ("-pwrong", "wrong/")] {
        let output = unrars(&dir, &["x", password, "mixed.rar", out]);
        assert_eq!(output.status.code(), Some(11), "{password}");
        let errors = stderr(&output);
        assert_eq!(
            errors.trim_end(),
            "Incorrect password for a.txt",
            "{password}"
        );
        assert!(stdout(&output).contains("Total errors: 1"), "{password}");
        assert_eq!(fs::read(dir.join(out).join("info.nfo")).unwrap(), b"info\n");
        assert!(!dir.join(out).join("a.txt").exists(), "{password}");
    }
    let output = unrars(&dir, &["x", "-p-", "mixed.rar", "info.nfo", "plain/"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(stderr(&output).is_empty(), "{}", stderr(&output));
    assert_eq!(fs::read(dir.join("plain/info.nfo")).unwrap(), b"info\n");

    let output = unrars(&dir, &["p", "-inul", "-p-", "mixed.rar", "nosuch"]);
    assert_eq!(output.status.code(), Some(10));
    let output = unrars(&dir, &["p", "-inul", "-pwrong", "mixed.rar", "info.nfo"]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, b"info\n");
    let output = unrars(&dir, &["x", "-idq", "-psecret", "mixed.rar", "right/"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(fs::read(dir.join("right/a.txt")).unwrap(), b"secret text\n");
}

/// Issue #564: without `-kb`, a member that fails its checksum is reported
/// and left out, and the members after it are still extracted or tested.
#[test]
fn a_checksum_error_does_not_stop_the_run() {
    let dir = scratch::case("unrars-checksum-continue");
    for version in [ArchiveVersion::Rar29, ArchiveVersion::Rar50] {
        let name = format!("{version:?}.rar");
        let path = dir.join(&name);
        write_three(&path, version);
        let mut bytes = fs::read(&path).unwrap();
        let start = bytes
            .windows(64)
            .position(|window| window == &payload()[..64])
            .unwrap();
        bytes[start + 1000] ^= 0xff;
        fs::write(&path, bytes).unwrap();

        let out = format!("out-{version:?}/");
        let output = unrars(&dir, &["x", &name, &out]);
        assert_eq!(output.status.code(), Some(3), "{version:?}");
        assert_eq!(
            stderr(&output).trim_end(),
            format!("{:<20} - checksum error", "mid.bin"),
            "{version:?}"
        );
        assert!(stdout(&output).contains("Total errors: 1"), "{version:?}");
        assert!(!dir.join(&out).join("mid.bin").exists(), "{version:?}");
        assert_eq!(fs::read(dir.join(&out).join("a.txt")).unwrap(), b"hello\n");
        assert_eq!(fs::read(dir.join(&out).join("z.txt")).unwrap(), b"after\n");

        let output = unrars(&dir, &["t", &name]);
        assert_eq!(output.status.code(), Some(3), "{version:?}");
        let text = stdout(&output);
        let tested = |name: &str, passed: bool| {
            text.lines().any(|line| {
                line.starts_with("Testing ")
                    && line.contains(name)
                    && line.ends_with("OK") == passed
            })
        };
        assert!(tested("a.txt", true), "{version:?}: {text}");
        assert!(tested("mid.bin", false), "{version:?}: {text}");
        assert!(tested("z.txt", true), "{version:?}: {text}");

        // A damaged member the command line doesn't ask for is no error.
        let only = format!("only-{version:?}/");
        let output = unrars(&dir, &["x", "-idq", &name, "z.txt", &only]);
        assert_eq!(
            output.status.code(),
            Some(0),
            "{version:?}: {}",
            stderr(&output)
        );
        assert_eq!(fs::read(dir.join(&only).join("z.txt")).unwrap(), b"after\n");
    }
}

/// The files under `root`, as `/`-separated relative paths.
fn files_under(root: &Path) -> Vec<String> {
    let mut found = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(at) = stack.pop() {
        for entry in fs::read_dir(at).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let parts: Vec<_> = path
                .strip_prefix(root)
                .unwrap()
                .components()
                .map(|part| part.as_os_str().to_string_lossy().into_owned())
                .collect();
            found.push(parts.join("/"));
        }
    }
    found.sort();
    found
}

/// Issue #564: a plain name is a path from the archive root and takes a
/// directory's contents with it; a wildcard without a path matches names in
/// any directory.
#[test]
fn masks_select_as_unrar_does() {
    let dir = scratch::case("unrars-mask-rules");
    let mut builder = Builder::new(ArchiveVersion::Rar50).store(true);
    builder
        .add_bytes(b"a.txt".to_vec(), b"root\n".to_vec(), None, None)
        .unwrap();
    builder.add_directory(b"sub".to_vec(), None, None).unwrap();
    for name in ["sub/a.txt", "sub/b.txt", "sub/deeper/a.txt"] {
        builder
            .add_bytes(name.as_bytes().to_vec(), b"x\n".to_vec(), None, None)
            .unwrap();
    }
    builder.write_to_path(&dir.join("masks.rar"), None).unwrap();
    let listed = |masks: &[&str]| {
        let mut args = vec!["lb", "masks.rar"];
        args.extend(masks);
        stdout(&unrars(&dir, &args))
    };
    assert_eq!(listed(&["a.txt"]), "a.txt\n");
    assert_eq!(
        listed(&["sub"]),
        "sub\nsub/a.txt\nsub/b.txt\nsub/deeper/a.txt\n"
    );
    assert_eq!(
        listed(&["*.txt"]),
        "a.txt\nsub/a.txt\nsub/b.txt\nsub/deeper/a.txt\n"
    );
    assert_eq!(listed(&["s*"]), "sub\n");
    assert_eq!(listed(&["deeper"]), "");

    for (mask, out, files) in [
        ("a.txt", "root", &["a.txt"][..]),
        (
            "sub",
            "tree",
            &["sub/a.txt", "sub/b.txt", "sub/deeper/a.txt"],
        ),
    ] {
        let output = unrars(&dir, &["x", "-idq", "masks.rar", mask, &format!("{out}/")]);
        assert_eq!(output.status.code(), Some(0), "{mask}: {}", stderr(&output));
        assert_eq!(files_under(&dir.join(out)), files, "{mask}");
    }
}

/// A RAR 5 archive holding two stored copies of `v.txt`, an older one with a
/// file version record as `rar -ver` writes it, then the latest, and `x;1`,
/// a file whose name only looks like a version. Built by hand, since rars
/// writes no version records.
fn write_versions(path: &Path) {
    fn vint(mut value: u64, out: &mut Vec<u8>) {
        loop {
            let byte = (value & 0x7f) as u8;
            value >>= 7;
            if value == 0 {
                out.push(byte);
                return;
            }
            out.push(byte | 0x80);
        }
    }
    fn block(header: &[u8], out: &mut Vec<u8>) {
        let mut sized = Vec::new();
        vint(header.len() as u64, &mut sized);
        sized.extend_from_slice(header);
        out.extend_from_slice(&rars::crc32::crc32(&sized).to_le_bytes());
        out.extend_from_slice(&sized);
    }
    fn file(name: &[u8], data: &[u8], version: Option<u64>, out: &mut Vec<u8>) {
        let mut extra = Vec::new();
        if let Some(version) = version {
            // Type 4, no flags, then the version number.
            let mut record = vec![4, 0];
            vint(version, &mut record);
            vint(record.len() as u64, &mut extra);
            extra.extend_from_slice(&record);
        }
        // A file header with a data area, and an extra area if there is one.
        let mut header = vec![2];
        vint(if extra.is_empty() { 0x02 } else { 0x03 }, &mut header);
        if !extra.is_empty() {
            vint(extra.len() as u64, &mut header);
        }
        vint(data.len() as u64, &mut header);
        // Flags (CRC32 present), size, attributes, CRC32, stored, Unix host.
        vint(0x04, &mut header);
        vint(data.len() as u64, &mut header);
        vint(0o100644, &mut header);
        header.extend_from_slice(&rars::crc32::crc32(data).to_le_bytes());
        vint(0, &mut header);
        vint(1, &mut header);
        vint(name.len() as u64, &mut header);
        header.extend_from_slice(name);
        header.extend_from_slice(&extra);
        block(&header, out);
        out.extend_from_slice(data);
    }
    let mut bytes = b"Rar!\x1a\x07\x01\x00".to_vec();
    block(&[1, 0, 0], &mut bytes);
    file(b"v.txt", b"one\n", Some(1), &mut bytes);
    file(b"v.txt", b"two\n", None, &mut bytes);
    file(b"x;1", b"semi\n", None, &mut bytes);
    block(&[5, 0, 0], &mut bytes);
    fs::write(path, bytes).unwrap();
}

/// Issue #564: older copies of a file are extracted only with `-ver`, and
/// listed either way.
#[test]
fn older_file_versions_need_ver() {
    let dir = scratch::case("unrars-versions");
    write_versions(&dir.join("ver.rar"));
    assert_eq!(
        stdout(&unrars(&dir, &["lb", "ver.rar"])),
        "v.txt;1\nv.txt\nx;1\n"
    );
    let output = unrars(&dir, &["x", "-idq", "ver.rar", "latest/"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(files_under(&dir.join("latest")), ["v.txt", "x;1"]);
    assert_eq!(fs::read(dir.join("latest/v.txt")).unwrap(), b"two\n");

    let output = unrars(&dir, &["x", "-idq", "-ver", "ver.rar", "all/"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(fs::read(dir.join("all/v.txt;1")).unwrap(), b"one\n");
    assert_eq!(fs::read(dir.join("all/v.txt")).unwrap(), b"two\n");
}

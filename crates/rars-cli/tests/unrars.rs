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

/// A member for [`rar5_by_hand`]: name, data, file version, compression info.
type HandMember<'a> = (&'a [u8], &'a [u8], Option<u64>, u64);

/// A RAR 5 archive of members with the given headers, built by hand for
/// headers rars doesn't write: file version records, or compression methods
/// from later versions. Each member's CRC32 is of its data.
fn rar5_by_hand(path: &Path, members: &[HandMember<'_>]) {
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
    let mut bytes = b"Rar!\x1a\x07\x01\x00".to_vec();
    block(&[1, 0, 0], &mut bytes);
    for &(name, data, version, compression) in members {
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
        // Flags (CRC32 present), size, attributes, CRC32, compression, Unix host.
        vint(0x04, &mut header);
        vint(data.len() as u64, &mut header);
        vint(0o100644, &mut header);
        header.extend_from_slice(&rars::crc32::crc32(data).to_le_bytes());
        vint(compression, &mut header);
        vint(1, &mut header);
        vint(name.len() as u64, &mut header);
        header.extend_from_slice(name);
        header.extend_from_slice(&extra);
        block(&header, &mut bytes);
        bytes.extend_from_slice(data);
    }
    block(&[5, 0, 0], &mut bytes);
    fs::write(path, bytes).unwrap();
}

/// Two stored copies of `v.txt`, an older one with a file version record as
/// `rar -ver` writes it, then the latest, and `x;1`, a file whose name only
/// looks like a version.
fn write_versions(path: &Path) {
    rar5_by_hand(
        path,
        &[
            (b"v.txt", b"one\n", Some(1), 0),
            (b"v.txt", b"two\n", None, 0),
            (b"x;1", b"semi\n", None, 0),
        ],
    );
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

/// Issue #565: an archive cut inside its last member's data gives every
/// member before the cut, whatever `-kb` says, and lists all three.
#[test]
fn a_cut_archive_gives_the_members_before_the_cut() {
    let dir = scratch::case("unrars-cut-member");
    for version in [ArchiveVersion::Rar29, ArchiveVersion::Rar50] {
        let name = format!("{version:?}.rar");
        let path = dir.join(&name);
        let mut builder = Builder::new(version).store(true);
        for (member, data) in [
            (&b"a.txt"[..], b"hello\n".to_vec()),
            (b"z.txt", b"after\n".to_vec()),
            (b"big.bin", payload()),
        ] {
            builder
                .add_bytes(member.to_vec(), data, None, None)
                .unwrap();
        }
        builder.write_to_path(&path, None).unwrap();
        let bytes = fs::read(&path).unwrap();
        let start = bytes
            .windows(64)
            .position(|window| window == &payload()[..64])
            .unwrap();
        fs::write(&path, &bytes[..start + 5000]).unwrap();

        let out = format!("out-{version:?}/");
        let output = unrars(&dir, &["x", &name, &out]);
        let errors = stderr(&output);
        assert_eq!(output.status.code(), Some(3), "{version:?}: {errors}");
        assert!(
            errors.contains(&format!("{:<20} - checksum error", "big.bin")),
            "{version:?}: {errors}"
        );
        assert!(
            errors.contains("Unexpected end of archive"),
            "{version:?}: {errors}"
        );
        assert!(!errors.contains("not RAR archive"), "{version:?}: {errors}");
        assert!(stdout(&output).contains("Total errors: 2"), "{version:?}");
        assert_eq!(
            files_under(&dir.join(&out)),
            ["a.txt", "z.txt"],
            "{version:?}"
        );

        let output = unrars(&dir, &["t", &name]);
        assert_eq!(output.status.code(), Some(3), "{version:?}");

        let output = unrars(&dir, &["lb", &name]);
        assert_eq!(output.status.code(), Some(1), "{version:?}");
        assert_eq!(stdout(&output), "a.txt\nz.txt\nbig.bin\n", "{version:?}");
        let output = unrars(&dir, &["l", &name]);
        assert_eq!(output.status.code(), Some(1), "{version:?}");
        assert!(stderr(&output).contains("Unexpected end of archive"));
    }
}

/// Issue #565: without `-kb`, a file header that fails its checksum is
/// reported as unrar does, and its member and those after it are read.
#[test]
fn a_damaged_file_header_is_read_past() {
    let dir = scratch::case("unrars-damaged-header");
    for version in [ArchiveVersion::Rar29, ArchiveVersion::Rar50] {
        let name = format!("{version:?}.rar");
        let path = dir.join(&name);
        write_three(&path, version);
        let mut bytes = fs::read(&path).unwrap();
        let at = bytes.windows(7).position(|v| v == b"mid.bin").unwrap();
        // Renames it to lid.bin, so the header fails its checksum.
        bytes[at] ^= 0x01;
        fs::write(&path, bytes).unwrap();
        for args in [&["x"][..], &["t"], &["l"], &["p", "-inul"]] {
            let mut args = args.to_vec();
            let out = format!("out-{version:?}/");
            args.push(&name);
            if args[0] == "x" {
                args.push(&out);
            }
            let output = unrars(&dir, &args);
            let errors = stderr(&output);
            assert_eq!(
                output.status.code(),
                Some(3),
                "{version:?} {args:?}: {errors}"
            );
            if args[0] != "p" {
                assert!(
                    errors.contains("lid.bin - the file header is corrupt"),
                    "{version:?} {args:?}: {errors}"
                );
                assert!(!errors.contains("ERROR"), "{version:?} {args:?}: {errors}");
            }
        }
        let out = dir.join(format!("out-{version:?}"));
        assert_eq!(fs::read(out.join("lid.bin")).unwrap(), payload());
        assert_eq!(fs::read(out.join("z.txt")).unwrap(), b"after\n");
    }
}

/// Issue #565: damage to the main archive header is named as unrar names it.
#[test]
fn a_damaged_main_header_is_named() {
    let dir = scratch::case("unrars-main-header");
    let path = write(&dir, "main.rar", None);
    let mut bytes = fs::read(&path).unwrap();
    // The main header's CRC, straight after the RAR 5 signature.
    bytes[8] ^= 0xff;
    fs::write(&path, bytes).unwrap();
    let output = unrars(&dir, &["t", "main.rar"]);
    let errors = stderr(&output);
    assert_eq!(output.status.code(), Some(3), "{errors}");
    assert!(
        errors.contains("Main archive header is corrupt"),
        "{errors}"
    );
}

/// Issue #565: a member compressed by a method this reader doesn't know is
/// reported in unrar's words, and the run goes on.
#[test]
fn an_unknown_method_is_reported_as_unrar_does() {
    let dir = scratch::case("unrars-unknown-method");
    // Method 1 with algorithm version 5, which no RAR writes yet.
    rar5_by_hand(
        &dir.join("new.rar"),
        &[
            (b"a.txt", &[0; 64], None, 5 | 1 << 7),
            (b"b.txt", b"plain\n", None, 0),
        ],
    );
    let output = unrars(&dir, &["x", "new.rar", "out/"]);
    let errors = stderr(&output);
    assert_eq!(output.status.code(), Some(2), "{errors}");
    assert_eq!(
        errors,
        "Unknown method in a.txt\nYou may need a newer version of RAR.\n"
    );
    assert_eq!(fs::read(dir.join("out/b.txt")).unwrap(), b"plain\n");
}

/// `unrars` with `input` piped to its stdin.
fn unrars_with_input(dir: &Path, args: &[&str], input: &[u8]) -> Output {
    use std::io::Write;
    let mut child = Command::new(env!("CARGO_BIN_EXE_unrars"))
        .current_dir(dir)
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    // It may stop reading before taking all of it.
    let _ = stdin.write_all(input);
    drop(stdin);
    child.wait_with_output().unwrap()
}

/// A stored RAR 5 volume set named `set.partN.rar` in `dir`: `a.txt`, then
/// `big.bin` ([`payload`]) across several volumes, then `z.txt` in the last.
/// Returns the number of volumes.
fn write_set(dir: &Path) -> usize {
    let mut builder = Builder::new(ArchiveVersion::Rar50).store(true);
    for (name, data) in [
        (&b"a.txt"[..], b"hello\n".to_vec()),
        (b"big.bin", payload()),
        (b"z.txt", b"after\n".to_vec()),
    ] {
        builder.add_bytes(name.to_vec(), data, None, None).unwrap();
    }
    let volumes = builder
        .volume_size(Some(8 * 1024))
        .build_volumes(None)
        .unwrap();
    assert!(volumes.len() >= 3);
    for (index, bytes) in volumes.iter().enumerate() {
        fs::write(dir.join(format!("set.part{}.rar", index + 1)), bytes).unwrap();
    }
    volumes.len()
}

/// Issue #566: `-vp` asks before each later volume and waits for the answer
/// on stdin, terminal or not.
#[test]
fn vp_asks_before_each_volume() {
    let dir = scratch::case("unrars-vp");
    let count = write_set(&dir);
    let output = unrars_with_input(
        &dir,
        &["x", "-vp", "set.part1.rar", "out/"],
        "\n".repeat(count).as_bytes(),
    );
    let errors = stderr(&output);
    assert_eq!(output.status.code(), Some(0), "{errors}");
    for index in 2..=count {
        let prompt = format!("Insert disk with set.part{index}.rar [C]ontinue, [Q]uit ");
        assert!(errors.contains(&prompt), "{errors}");
    }
    assert_eq!(fs::read(dir.join("out/big.bin")).unwrap(), payload());
    assert_eq!(fs::read(dir.join("out/z.txt")).unwrap(), b"after\n");

    // With nothing to read on stdin, the run stops there.
    let output = unrars(&dir, &["x", "-vp", "set.part1.rar", "closed/"]);
    assert_eq!(output.status.code(), Some(12), "{}", stderr(&output));
    assert!(stdout(&output).contains("Program aborted"));
    assert!(!dir.join("closed/big.bin").exists());
    // Quitting leaves the volume missing.
    let output = unrars_with_input(&dir, &["x", "-vp", "set.part1.rar", "quit/"], b"q\n");
    assert_eq!(output.status.code(), Some(6), "{}", stderr(&output));
    assert!(stderr(&output).contains("Cannot find volume set.part2.rar"));
}

/// Issue #566: named by a later volume, a set is read from its first.
#[test]
fn a_set_named_by_a_later_volume_starts_at_the_first() {
    let dir = scratch::case("unrars-middle-volume");
    write_set(&dir);
    let output = unrars(&dir, &["x", "set.part2.rar", "out/"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(stdout(&output).contains("Extracting from set.part1.rar"));
    assert_eq!(files_under(&dir.join("out")), ["a.txt", "big.bin", "z.txt"]);
    assert_eq!(fs::read(dir.join("out/big.bin")).unwrap(), payload());
}

/// Issue #566: `l -v` lists each volume in turn, then a grand total, and
/// the Details line gives the volume's number.
#[test]
fn l_v_lists_every_volume() {
    let dir = scratch::case("unrars-list-volumes");
    let count = write_set(&dir);
    let output = unrars(&dir, &["l", "-v", "set.part1.rar"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let text = stdout(&output);
    for index in 1..=count {
        assert!(
            text.contains(&format!(
                "Archive: set.part{index}.rar\nDetails: RAR 5, volume {index}\n"
            )),
            "{text}"
        );
    }
    let total = format!("{:>21}{:>21}\n", payload().len() + 12, 3);
    assert!(text.ends_with(&format!("{total}\n")), "{text}");

    let output = unrars(&dir, &["l", "set.part1.rar"]);
    let text = stdout(&output);
    assert_eq!(text.matches("Archive:").count(), 1, "{text}");
    assert!(text.contains("Details: RAR 5, volume 1\n"), "{text}");
    let output = unrars(&dir, &["lb", "-v", "set.part1.rar"]);
    let names = stdout(&output);
    assert_eq!(names.matches("big.bin").count(), count, "{names}");
    assert!(names.starts_with("a.txt\nbig.bin\n"), "{names}");
    assert!(names.ends_with("big.bin\nz.txt\n"), "{names}");
}

/// Issue #566: a damaged volume in the middle of a split member is named,
/// and the members after it in the set are still extracted.
#[test]
fn a_damaged_volume_is_named_and_the_set_goes_on() {
    let dir = scratch::case("unrars-damaged-volume");
    write_set(&dir);
    let path = dir.join("set.part2.rar");
    let mut bytes = fs::read(&path).unwrap();
    let at = bytes.len() / 2;
    bytes[at] ^= 0xff;
    fs::write(&path, bytes).unwrap();
    let output = unrars(&dir, &["x", "set.part1.rar", "out/"]);
    let errors = stderr(&output);
    assert_eq!(output.status.code(), Some(3), "{errors}");
    assert_eq!(
        errors,
        format!(
            "{name:<20} : packed data checksum error in volume set.part2.rar\n\
             {name:<20} - checksum error\n",
            name = "big.bin"
        )
    );
    assert_eq!(files_under(&dir.join("out")), ["a.txt", "z.txt"]);
    assert_eq!(fs::read(dir.join("out/z.txt")).unwrap(), b"after\n");
}

/// Issue #566: a volume cut short in the middle of a split member loses
/// that member, and the members after it are still extracted.
#[test]
fn a_cut_middle_volume_loses_only_its_member() {
    let dir = scratch::case("unrars-cut-volume");
    write_set(&dir);
    let path = dir.join("set.part2.rar");
    let bytes = fs::read(&path).unwrap();
    fs::write(&path, &bytes[..bytes.len() / 2]).unwrap();
    let output = unrars(&dir, &["x", "set.part1.rar", "out/"]);
    let errors = stderr(&output);
    assert_eq!(output.status.code(), Some(3), "{errors}");
    assert!(
        errors.contains(&format!("{:<20} - checksum error", "big.bin")),
        "{errors}"
    );
    assert!(errors.contains("Unexpected end of archive"), "{errors}");
    assert!(!errors.contains("set.part1.rar - "), "{errors}");
    assert_eq!(files_under(&dir.join("out")), ["a.txt", "z.txt"]);
}

/// Issue #566: `-kb` keeps what a split member's volumes held before the
/// missing one.
#[test]
fn kb_keeps_a_split_member_up_to_a_missing_volume() {
    let dir = scratch::case("unrars-kb-missing-volume");
    write_set(&dir);
    fs::remove_file(dir.join("set.part2.rar")).unwrap();
    let output = unrars(&dir, &["x", "-kb", "set.part1.rar", "out/"]);
    assert_eq!(output.status.code(), Some(6), "{}", stderr(&output));
    assert!(stderr(&output).contains("Cannot find volume set.part2.rar"));
    let kept = fs::read(dir.join("out/big.bin")).unwrap();
    assert!(!kept.is_empty() && kept.len() < payload().len());
    assert_eq!(kept, payload()[..kept.len()]);
}

/// `a.txt`, `info.nfo` and `sub/` holding `a.txt`, `b.txt` and `deeper/a.txt`.
fn write_tree(path: &Path) {
    let mut builder = Builder::new(ArchiveVersion::Rar50).store(true);
    builder.add_directory(b"sub".to_vec(), None, None).unwrap();
    for name in [
        "a.txt",
        "info.nfo",
        "sub/a.txt",
        "sub/b.txt",
        "sub/deeper/a.txt",
    ] {
        builder
            .add_bytes(
                name.as_bytes().to_vec(),
                name.as_bytes().to_vec(),
                None,
                None,
            )
            .unwrap();
    }
    builder.write_to_path(path, None).unwrap();
}

/// Issue #568: the switches that choose which files are written, and where.
#[test]
fn selection_and_destination_switches() {
    let dir = scratch::case("unrars-selection-switches");
    write_tree(&dir.join("tree.rar"));
    let all = [
        "a.txt",
        "info.nfo",
        "sub/a.txt",
        "sub/b.txt",
        "sub/deeper/a.txt",
    ];
    for (switches, out, files) in [
        (
            &["-x*.nfo"][..],
            "x",
            &["a.txt", "sub/a.txt", "sub/b.txt", "sub/deeper/a.txt"][..],
        ),
        (&["-x*.nfo", "-xsub"], "x2", &all[..1]),
        (&["-n*.nfo"], "n", &all[1..2]),
        (
            &["-n*.txt", "-xsub/deeper"],
            "nx",
            &["a.txt", "sub/a.txt", "sub/b.txt"],
        ),
        (&["-apsub"], "ap", &["a.txt", "b.txt", "deeper/a.txt"]),
        (&["-ap/sub/"], "ap2", &["a.txt", "b.txt", "deeper/a.txt"]),
        (&["-ad", "-x*.txt"], "ad", &["tree/info.nfo"]),
        (&["-ep", "-o+"], "ep", &["a.txt", "b.txt", "info.nfo"]),
    ] {
        let destination = format!("{out}/");
        let mut args = vec!["x", "-idq"];
        args.extend(switches);
        args.extend(["tree.rar", &destination]);
        let output = unrars(&dir, &args);
        assert_eq!(
            output.status.code(),
            Some(0),
            "{switches:?}: {}",
            stderr(&output)
        );
        assert_eq!(files_under(&dir.join(out)), files, "{switches:?}");
    }
    assert_eq!(fs::read(dir.join("ap/b.txt")).unwrap(), b"sub/b.txt");

    let list = dir.join("excluded.lst");
    fs::write(&list, "*.nfo\r\nsub\n").unwrap();
    let output = unrars(&dir, &["x", "-idq", "-x@excluded.lst", "tree.rar", "list/"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(files_under(&dir.join("list")), ["a.txt"]);

    let output = unrars(&dir, &["x", "-idq", "-optarget", "tree.rar", "a.txt"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(files_under(&dir.join("target")), ["a.txt"]);

    assert_eq!(
        stdout(&unrars(&dir, &["lb", "-x*.txt", "tree.rar"])),
        "sub\ninfo.nfo\n"
    );
}

/// Issue #568: a switch unrars can't honour is refused by name, not ignored.
#[test]
fn unsupported_selection_switches_are_refused() {
    let dir = scratch::case("unrars-refused-switches");
    write_tree(&dir.join("tree.rar"));
    for switch in [
        "-ta20200101",
        "-tb2020",
        "-sl100",
        "-f",
        "-u",
        "-ep3",
        "-ad1",
        "-ola",
        "-cl",
    ] {
        let output = unrars(&dir, &["x", switch, "tree.rar", "out/"]);
        assert_eq!(output.status.code(), Some(7), "{switch}");
        assert_eq!(
            stderr(&output).trim_end(),
            format!("ERROR: unrars does not support the {switch} switch yet"),
        );
        assert!(!dir.join("out").exists(), "{switch}");
    }
    // Cosmetic ones are still accepted.
    let output = unrars(&dir, &["x", "-idq", "-ai", "-c-", "tree.rar", "out/"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
}

/// Issue #568: `-ol-` leaves symbolic links out.
#[cfg(unix)]
#[test]
fn ol_minus_leaves_symlinks_out() {
    let dir = scratch::case("unrars-ol-minus");
    let mut builder = Builder::new(ArchiveVersion::Rar50).store(true);
    builder
        .add_bytes(b"a.txt".to_vec(), b"hello\n".to_vec(), None, None)
        .unwrap();
    builder
        .add_unix_symlink(b"link.txt".to_vec(), b"a.txt".to_vec(), false, None, None)
        .unwrap();
    builder.write_to_path(&dir.join("ln.rar"), None).unwrap();
    let output = unrars(&dir, &["x", "-idq", "-ol-", "ln.rar", "out/"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(fs::symlink_metadata(dir.join("out/link.txt")).is_err());
    assert_eq!(fs::read(dir.join("out/a.txt")).unwrap(), b"hello\n");
    let output = unrars(&dir, &["x", "-idq", "ln.rar", "links/"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(fs::symlink_metadata(dir.join("links/link.txt"))
        .unwrap()
        .file_type()
        .is_symlink());
}

/// Issue #568: `-ierr` sends every message to stderr, listings included;
/// `p` still writes the file's bytes to stdout.
#[test]
fn ierr_sends_messages_to_stderr() {
    let dir = scratch::case("unrars-ierr");
    write(&dir, "plain.rar", None);
    for args in [
        &["x", "-ierr", "plain.rar", "out/"][..],
        &["l", "-ierr", "plain.rar"],
    ] {
        let output = unrars(&dir, args);
        assert_eq!(output.status.code(), Some(0), "{args:?}");
        assert!(output.stdout.is_empty(), "{args:?}: {}", stdout(&output));
        assert!(stderr(&output).contains("a.txt"), "{args:?}");
    }
    let output = unrars(&dir, &["p", "-ierr", "-idc", "plain.rar", "a.txt"]);
    assert_eq!(output.stdout, b"hello\n");
}

/// Issue #568: with no terminal, the password is read from a line of stdin.
#[test]
fn reads_a_password_from_stdin() {
    let dir = scratch::case("unrars-stdin-password");
    write(&dir, "enc.rar", Some(b"secret"));
    for (args, out, prompt) in [
        (
            &["x", "-idq"][..],
            "asked/",
            "Enter password (will not be echoed) for a.txt: ",
        ),
        (
            &["x", "-idq", "-p"],
            "given/",
            "Enter password (will not be echoed): ",
        ),
    ] {
        let mut args = args.to_vec();
        args.extend(["enc.rar", out]);
        let output = unrars_with_input(&dir, &args, b"secret\n");
        assert_eq!(
            output.status.code(),
            Some(0),
            "{args:?}: {}",
            stderr(&output)
        );
        assert!(stderr(&output).contains(prompt), "{}", stderr(&output));
        assert_eq!(fs::read(dir.join(out).join("a.txt")).unwrap(), b"hello\n");
    }
    // Nothing on stdin: the members that need it fail.
    let output = unrars(&dir, &["x", "-idq", "enc.rar", "none/"]);
    assert_eq!(output.status.code(), Some(11), "{}", stderr(&output));
    let output = unrars(&dir, &["x", "-idq", "-p", "enc.rar", "none/"]);
    assert_eq!(output.status.code(), Some(12), "{}", stderr(&output));
}

/// Issue #568: RAR 4 keeps no password check, so a wrong password reads as
/// a damaged member, as unrar says.
#[test]
fn a_wrong_rar4_password_is_a_checksum_error() {
    let dir = scratch::case("unrars-rar4-password");
    let mut builder = Builder::new(ArchiveVersion::Rar29)
        .store(true)
        .password(Some(b"secret".to_vec()));
    builder
        .add_bytes(b"a.txt".to_vec(), b"hello\n".to_vec(), None, None)
        .unwrap();
    builder.write_to_path(&dir.join("enc4.rar"), None).unwrap();
    let output = unrars(&dir, &["x", "-idq", "-pwrong", "enc4.rar", "out/"]);
    assert_eq!(output.status.code(), Some(3));
    assert_eq!(
        stderr(&output),
        "Checksum error in the encrypted file a.txt. Corrupt file or wrong password.\n"
    );
    let output = unrars(&dir, &["x", "-idq", "-psecret", "enc4.rar", "out/"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
}

/// Issue #567: `p` writes the member's bytes and nothing else, banner or not.
#[test]
fn p_prints_only_the_member() {
    let dir = scratch::case("unrars-p-banner");
    write(&dir, "plain.rar", None);
    let output = unrars(&dir, &["p", "plain.rar", "a.txt"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(output.stdout, b"hello\n");
}

/// 2011-06-12 10:53 UTC: 06:53 in New York, in daylight saving time.
const SUMMER: i64 = 1_307_875_980;

/// Issue #567: the listing columns, marker and Details line unrar shows.
#[test]
fn listings_show_what_unrar_shows() {
    let dir = scratch::case("unrars-listing-details");
    let when = Some(rars::Timestamp::from_unix_seconds(SUMMER));
    let mut builder = Builder::new(ArchiveVersion::Rar50)
        .store(true)
        .solid(true)
        .recovery_percent(Some(5))
        .comment(Some(b"made by a test\n".to_vec()));
    builder
        .add_bytes(b"a.txt".to_vec(), b"hello\n".to_vec(), when, Some(0o644))
        .unwrap();
    builder
        .add_bytes(
            b"lock.txt".to_vec(),
            b"locked\n".to_vec(),
            when,
            Some(0o644),
        )
        .unwrap();
    builder
        .set_entry_encryption(b"lock.txt", Some(b"secret".to_vec()), None)
        .unwrap();
    builder.write_to_path(&dir.join("full.rar"), None).unwrap();

    let output = unrars(&dir, &["l", "-idc", "full.rar"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let text = stdout(&output);
    assert!(
        text.starts_with("\nArchive comment:\nmade by a test\n\n\nArchive: full.rar\n"),
        "{text}"
    );
    assert!(
        text.contains("Details: RAR 5, solid, recovery record\n"),
        "{text}"
    );
    assert!(text.contains(" Attributes       Size     Date    Time   Name\n"));
    assert!(text.contains("\n -rw-r--r--          6  "), "{text}");
    assert!(text.contains("\n*-rw-r--r--          7  "), "{text}");
    assert!(text.contains(&format!("{:>22}{:>21}\n", 13, 2)), "{text}");

    let output = unrars(&dir, &["v", "-idc", "full.rar"]);
    let text = stdout(&output);
    let crc = rars::crc32::crc32(b"hello\n");
    assert!(
        text.contains(" -rw-r--r--          6         ")
            && text.contains(&format!("  {crc:08X}  a.txt\n")),
        "{text}"
    );
    assert!(text.contains("Packed Ratio"), "{text}");

    let output = unrars(&dir, &["lt", "-idc", "-psecret", "full.rar"]);
    let text = stdout(&output);
    for line in [
        "        Name: a.txt\n        Type: File\n        Size: 6\n",
        &format!("       CRC32: {crc:08X}\n     Host OS: Unix\n"),
        "       Flags: solid encrypted \n",
    ] {
        assert!(text.contains(line), "{line:?}: {text}");
    }
}

/// Issue #567: an archive whose headers need a password no one gave is
/// still named, with its Details, as unrar does.
#[test]
fn a_listing_without_the_header_password_names_the_archive() {
    let dir = scratch::case("unrars-listing-locked");
    builder(Some(b"secret"))
        .header_encryption(true)
        .write_to_path(&dir.join("henc.rar"), None)
        .unwrap();
    let output = unrars(&dir, &["l", "-idc", "-p-", "henc.rar"]);
    assert_eq!(output.status.code(), Some(11), "{}", stderr(&output));
    assert_eq!(stderr(&output), "Incorrect password for henc.rar\n");
    assert_eq!(
        stdout(&output),
        "\nArchive: henc.rar\nDetails: RAR 5, encrypted headers\n  0 files\n\n"
    );
}

/// Issue #567: RAR 5 times are UTC and listed in local time.
#[cfg(unix)]
#[test]
fn listings_show_rar5_times_in_local_time() {
    let dir = scratch::case("unrars-listing-local-time");
    let mut builder = Builder::new(ArchiveVersion::Rar50).store(true);
    builder
        .add_bytes(
            b"a.txt".to_vec(),
            b"hello\n".to_vec(),
            Some(rars::Timestamp::from_unix_seconds(SUMMER)),
            None,
        )
        .unwrap();
    builder
        .write_to_path(&dir.join("summer.rar"), None)
        .unwrap();
    for (zone, shown) in [
        ("America/New_York", "2011-06-12 06:53"),
        ("UTC", "2011-06-12 10:53"),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_unrars"))
            .current_dir(&dir)
            .env("TZ", zone)
            .args(["l", "summer.rar"])
            .output()
            .unwrap();
        let text = stdout(&output);
        assert!(
            text.contains(&format!("  {shown}  a.txt\n")),
            "{zone}: {text}"
        );
    }
}

/// Runs `unrars` with stdout piped, reads `keep` bytes of it, then closes
/// the pipe, as `| head -c` does. Returns the exit code and stderr.
fn unrars_into_closed_pipe(dir: &Path, args: &[&str], keep: usize) -> (Option<i32>, String) {
    use std::io::Read;
    let mut child = Command::new(env!("CARGO_BIN_EXE_unrars"))
        .current_dir(dir)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let mut kept = vec![0; keep];
    stdout.read_exact(&mut kept).unwrap();
    drop(stdout);
    let output = child.wait_with_output().unwrap();
    (output.status.code(), stderr(&output))
}

/// Issue #574: a reader that closes stdout early ends the run quietly, with
/// the status a shell gives a process SIGPIPE kills, never a panic.
#[cfg(unix)]
#[test]
fn a_closed_stdout_ends_the_run_quietly() {
    let dir = scratch::case("unrars-broken-pipe");
    let big: Vec<u8> = (0..4_000_000u32).map(|n| (n * 13 % 251) as u8).collect();
    let mut builder = Builder::new(ArchiveVersion::Rar50).store(true);
    builder
        .add_bytes(b"big.bin".to_vec(), big, None, None)
        .unwrap();
    for index in 0..3000 {
        builder
            .add_bytes(
                format!("many/{index:04}.txt").into_bytes(),
                b"x\n".to_vec(),
                None,
                None,
            )
            .unwrap();
    }
    builder.write_to_path(&dir.join("big.rar"), None).unwrap();
    for args in [
        &["p", "-inul", "big.rar", "big.bin"][..],
        &["p", "big.rar", "big.bin"],
        &["l", "big.rar"],
        &["v", "big.rar"],
        &["lb", "big.rar"],
        &["t", "big.rar"],
        &["x", "-o+", "big.rar", "out/"],
    ] {
        let (code, errors) = unrars_into_closed_pipe(&dir, args, 100);
        assert_eq!(code, Some(141), "{args:?}: {errors}");
        assert!(errors.is_empty(), "{args:?}: {errors}");
    }
}

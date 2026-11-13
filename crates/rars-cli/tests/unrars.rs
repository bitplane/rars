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

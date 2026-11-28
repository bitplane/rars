#![cfg(unix)]

#[path = "support/scratch.rs"]
mod scratch;
use rars::{Archive, ArchiveReader, ArchiveVersion, Builder};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output};

const SYMLINK: u64 = 1;
const HARD_LINK: u64 = 4;
const MTIME: u32 = 1_600_000_000;

fn archive(path: &Path) {
    write_rar5(path, "x");
}

fn write_rar5(path: &Path, hard_target: &str) {
    let entries = vec![
        directory("d", 0o040700),
        unix_file("d/f", 0o604),
        unix_file("x", 0o750),
        unix_file("ro", 0o400),
        link("sl", SYMLINK, "x"),
        link("hl", HARD_LINK, hard_target),
    ];
    write_entries(path, &entries);
}

/// `real/`, then links leading inside, up and to an absolute path, each with a member stored under it.
fn write_links(path: &Path, absolute: &Path) {
    let absolute = absolute.to_str().unwrap();
    let entries = vec![
        directory("real", 0o040755),
        link("inlink", SYMLINK, "real"),
        link("up", SYMLINK, "../outside"),
        link("abs", SYMLINK, absolute),
        link("lone", SYMLINK, absolute),
        unix_file("inlink/file.txt", 0o644),
        unix_file("up/file.txt", 0o644),
        unix_file("abs/file.txt", 0o644),
    ];
    write_entries(path, &entries);
}

fn unix(entry: rars::rar50::ArchiveEntry, mode: u64) -> rars::rar50::ArchiveEntry {
    entry.with_host_os(1).with_attributes(mode)
}

fn directory(name: &str, mode: u64) -> rars::rar50::ArchiveEntry {
    let entry = rars::rar50::ArchiveEntry::new(name, rars::EntrySource::from_bytes(Vec::new()));
    unix(entry.with_directory(true), mode)
}

fn unix_file(name: &str, mode: u64) -> rars::rar50::ArchiveEntry {
    let entry =
        rars::rar50::ArchiveEntry::new(name, rars::EntrySource::from_bytes(b"payload".to_vec()));
    unix(entry.with_mtime(Some(MTIME)), 0o100000 | mode)
}

fn link(name: &str, kind: u64, target: &str) -> rars::rar50::ArchiveEntry {
    use rars::rar50::{ArchiveEntry, Block};
    // A redirection can't be built outside the crate, so one is read back.
    let mut builder = Builder::new(ArchiveVersion::Rar50);
    builder
        .add_unix_symlink(b"x".to_vec(), b"x".to_vec(), false, None, None)
        .unwrap();
    let Archive::Rar50Plus(rar5) = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap()
    else {
        unreachable!()
    };
    let mut redirection = rar5
        .blocks
        .iter()
        .find_map(|block| match block {
            Block::File(file) => file.redirection.clone(),
            _ => None,
        })
        .unwrap();
    redirection.redirection_type = kind;
    redirection.target_name = target.as_bytes().to_vec();
    let entry = ArchiveEntry::new(name, rars::EntrySource::from_bytes(Vec::new()))
        .with_redirection(Some(redirection));
    if kind == SYMLINK {
        unix(entry, 0o120777)
    } else {
        unix(entry.with_redirection_size(Some(7)), 0o100750)
    }
}

fn write_entries(path: &Path, entries: &[rars::rar50::ArchiveEntry]) {
    use rars::rar50::{self, ArchiveExtras, WriterOptions};
    let mut out = Vec::new();
    rar50::write_streaming_archive_to(
        entries,
        WriterOptions::default(),
        ArchiveExtras::default(),
        &rars::WriterResources::default(),
        &mut out,
    )
    .unwrap();
    fs::write(path, out).unwrap();
}

fn rars_extract(archive: &Path, out: &Path, extra: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rars"))
        .arg("extract")
        .args(extra)
        .arg(archive)
        .arg(out)
        .output()
        .unwrap()
}

fn unrars(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_unrars"))
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap()
}

fn succeeded(output: &Output) {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn umask_defaults(root: &Path) -> (u32, u32) {
    let file = root.join("umask-file");
    let dir = root.join("umask-dir");
    fs::File::create(&file).unwrap();
    fs::create_dir(&dir).unwrap();
    (mode(&file), mode(&dir))
}

fn modes(out: &Path) -> [u32; 5] {
    ["d", "d/f", "x", "ro", "hl"].map(|name| mode(&out.join(name)))
}

#[test]
fn ignore_attributes_leaves_files_and_directories_at_the_umask_defaults() {
    let root = scratch::case("cli-ignore-attributes");
    let rar = root.join("modes.rar");
    archive(&rar);
    let (file, dir) = umask_defaults(&root);
    for staging in [&[][..], &["--in-place"]] {
        let kept = root.join(format!("kept{}", staging.len()));
        succeeded(&rars_extract(&rar, &kept, staging));
        assert_eq!(modes(&kept), [0o700, 0o604, 0o750, 0o400, 0o750]);

        let ignored = root.join(format!("ignored{}", staging.len()));
        let args = [staging, &["--ignore-attributes"]].concat();
        succeeded(&rars_extract(&rar, &ignored, &args));
        assert_eq!(modes(&ignored), [dir, file, file, file, file], "{args:?}");
        assert_eq!(fs::read(ignored.join("ro")).unwrap(), b"payload");
        let modified = fs::metadata(ignored.join("x")).unwrap().modified().unwrap();
        assert_eq!(
            modified,
            std::time::UNIX_EPOCH + std::time::Duration::from_secs(MTIME.into())
        );
    }
}

#[test]
fn unrars_ai_leaves_files_and_directories_at_the_umask_defaults() {
    let root = scratch::case("unrars-ai-modes");
    archive(&root.join("modes.rar"));
    let (file, dir) = umask_defaults(&root);
    succeeded(&unrars(&root, &["x", "-idq", "modes.rar", "kept/"]));
    assert_eq!(
        modes(&root.join("kept")),
        [0o700, 0o604, 0o750, 0o400, 0o750]
    );
    succeeded(&unrars(
        &root,
        &["x", "-idq", "-ai", "modes.rar", "ignored/"],
    ));
    assert_eq!(modes(&root.join("ignored")), [dir, file, file, file, file]);
}

#[test]
fn skipping_symlinks_keeps_hard_links() {
    let root = scratch::case("cli-skip-symlinks");
    let rar = root.join("modes.rar");
    archive(&rar);
    let is_symlink = |path: &Path| {
        fs::symlink_metadata(path)
            .ok()
            .map(|meta| meta.file_type().is_symlink())
    };
    succeeded(&rars_extract(&rar, &root.join("all"), &[]));
    assert_eq!(is_symlink(&root.join("all/sl")), Some(true));

    succeeded(&rars_extract(&rar, &root.join("cli"), &["--skip-symlinks"]));
    succeeded(&unrars(
        &root,
        &["x", "-idq", "-ol-", "modes.rar", "unrars/"],
    ));
    for out in ["cli", "unrars"] {
        let out = root.join(out);
        assert_eq!(is_symlink(&out.join("sl")), None, "{out:?}");
        assert_eq!(is_symlink(&out.join("hl")), Some(false), "{out:?}");
        assert_eq!(fs::read(out.join("hl")).unwrap(), b"payload");
    }
}

#[test]
fn a_hard_link_to_a_symlink_left_out_fails() {
    let root = scratch::case("cli-skip-symlinks-hard-link");
    let rar = root.join("links.rar");
    write_rar5(&rar, "sl");
    let cli = rars_extract(&rar, &root.join("cli"), &["--skip-symlinks"]);
    let unrars = unrars(&root, &["x", "-idq", "-ol-", "links.rar", "unrars/"]);
    for (output, out) in [(cli, "cli"), (unrars, "unrars")] {
        let out = root.join(out);
        assert!(!output.status.success(), "{out:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("symbolic link left out"),
            "{out:?}: {stderr}"
        );
        assert!(fs::symlink_metadata(out.join("hl")).is_err(), "{out:?}");
        assert!(fs::symlink_metadata(out.join("sl")).is_err(), "{out:?}");
        assert_eq!(fs::read(out.join("x")).unwrap(), b"payload", "{out:?}");
    }
}

fn read_link(path: &Path) -> Option<std::path::PathBuf> {
    fs::read_link(path).ok()
}

fn is_directory(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|meta| meta.is_dir())
}

#[test]
fn links_inside_are_made_and_give_way_to_a_member_stored_under_them() {
    let root = scratch::case("cli-symlinks-inside");
    let victim = root.join("victim");
    fs::create_dir(&victim).unwrap();
    let rar = root.join("links.rar");
    write_links(&rar, &victim);
    let cli = rars_extract(&rar, &root.join("cli/out"), &[]);
    fs::create_dir(root.join("unrars")).unwrap();
    let unrars = unrars(&root.join("unrars"), &["x", "-idq", "../links.rar", "out/"]);
    for (output, out) in [(cli, "cli"), (unrars, "unrars")] {
        assert_eq!(output.status.code(), Some(1), "{out}");
        let out = root.join(out).join("out");
        for name in ["inlink", "up", "abs"] {
            assert!(is_directory(&out.join(name)), "{out:?} {name}");
            assert_eq!(
                fs::read(out.join(name).join("file.txt")).unwrap(),
                b"payload"
            );
        }
        assert_eq!(read_link(&out.join("lone")), None, "{out:?}");
        assert_eq!(
            fs::read_dir(out.join("real")).unwrap().count(),
            0,
            "{out:?}"
        );
    }
    assert_eq!(fs::read_dir(&victim).unwrap().count(), 0);
}

#[test]
fn every_link_is_made_as_stored_and_never_written_through() {
    let root = scratch::case("cli-symlinks-all");
    let victim = root.join("victim");
    fs::create_dir(&victim).unwrap();
    let rar = root.join("links.rar");
    write_links(&rar, &victim);
    let cli = rars_extract(&rar, &root.join("cli/out"), &["--symlinks=all"]);
    fs::create_dir(root.join("unrars")).unwrap();
    let unrars = unrars(
        &root.join("unrars"),
        &["x", "-idq", "-ola", "../links.rar", "out/"],
    );
    for (output, out) in [(cli, "cli"), (unrars, "unrars")] {
        succeeded(&output);
        let out = root.join(out).join("out");
        assert_eq!(
            read_link(&out.join("lone")),
            Some(victim.clone()),
            "{out:?}"
        );
        for name in ["inlink", "up", "abs"] {
            assert!(is_directory(&out.join(name)), "{out:?} {name}");
            assert_eq!(
                fs::read(out.join(name).join("file.txt")).unwrap(),
                b"payload"
            );
        }
    }
    assert_eq!(fs::read_dir(&victim).unwrap().count(), 0);
    assert!(!root.join("cli/outside").exists());
    assert!(!root.join("unrars/outside").exists());
}

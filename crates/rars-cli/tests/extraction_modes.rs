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
    use rars::rar50::{self, ArchiveEntry, ArchiveExtras, Block, WriterOptions};
    use rars::EntrySource;
    // A redirection can't be built outside the crate, so one is read back.
    let mut builder = Builder::new(ArchiveVersion::Rar50);
    builder
        .add_unix_symlink(b"x".to_vec(), b"x".to_vec(), false, None, None)
        .unwrap();
    let Archive::Rar50Plus(rar5) = ArchiveReader::read_owned(builder.to_bytes().unwrap()).unwrap()
    else {
        unreachable!()
    };
    let symlink = rar5
        .blocks
        .iter()
        .find_map(|block| match block {
            Block::File(file) => file.redirection.clone(),
            _ => None,
        })
        .unwrap();
    let unix = |entry: ArchiveEntry, mode: u64| entry.with_host_os(1).with_attributes(mode);
    let file = |name: &str, mode: u64| {
        unix(
            ArchiveEntry::new(name, EntrySource::from_bytes(b"payload".to_vec()))
                .with_mtime(Some(MTIME)),
            0o100000 | mode,
        )
    };
    let link = |name: &str, kind: u64, target: &str| {
        let mut redirection = symlink.clone();
        redirection.redirection_type = kind;
        redirection.target_name = target.as_bytes().to_vec();
        let entry = ArchiveEntry::new(name, EntrySource::from_bytes(Vec::new()))
            .with_redirection(Some(redirection));
        if kind == SYMLINK {
            unix(entry, 0o120777)
        } else {
            unix(entry.with_redirection_size(Some(7)), 0o100750)
        }
    };
    let entries = vec![
        unix(
            ArchiveEntry::new("d", EntrySource::from_bytes(Vec::new())).with_directory(true),
            0o040700,
        ),
        file("d/f", 0o604),
        file("x", 0o750),
        file("ro", 0o400),
        link("sl", SYMLINK, "x"),
        link("hl", HARD_LINK, hard_target),
    ];
    let mut out = Vec::new();
    rar50::write_streaming_archive_to(
        &entries,
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

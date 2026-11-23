#[path = "support/scratch.rs"]
mod scratch;

use rars::{ArchiveVersion, Builder};
use std::fs;
use std::path::Path;
use std::process::{Command, Output};

fn write_archive(path: &Path, version: ArchiveVersion, entries: &[(&[u8], &[u8])]) -> Vec<u8> {
    let mut builder = Builder::new(version).store(true);
    for &(name, data) in entries {
        builder
            .add_bytes(name.to_vec(), data.to_vec(), None, None)
            .unwrap();
    }
    let bytes = builder.to_bytes().unwrap();
    fs::write(path, &bytes).unwrap();
    bytes
}

fn extract(archive: &Path, destination: &Path, extra: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rars"))
        .args(["x", "--overwrite=always"])
        .args(extra)
        .arg(archive)
        .arg(destination)
        .output()
        .unwrap()
}

#[cfg(unix)]
#[test]
fn overwriting_an_output_hard_link_preserves_its_outside_target() {
    for version in [
        ArchiveVersion::Rar14,
        ArchiveVersion::Rar29,
        ArchiveVersion::Rar50,
    ] {
        let root = scratch::case("extraction-hardlink-publication");
        let archive = root.join("archive.rar");
        write_archive(&archive, version, &[(b"file.txt", b"new archive contents")]);
        let destination = root.join("out");
        fs::create_dir(&destination).unwrap();
        let outside = root.join("outside.txt");
        fs::write(&outside, b"original outside contents").unwrap();
        fs::hard_link(&outside, destination.join("file.txt")).unwrap();
        let result = extract(&archive, &destination, &[]);
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(fs::read(&outside).unwrap(), b"original outside contents");
        assert_eq!(
            fs::read(destination.join("file.txt")).unwrap(),
            b"new archive contents"
        );
        assert_eq!(fs::read_dir(destination).unwrap().count(), 1);
    }
}

#[test]
fn checksum_failure_keeps_verified_members_and_existing_files() {
    for version in [
        ArchiveVersion::Rar14,
        ArchiveVersion::Rar29,
        ArchiveVersion::Rar50,
    ] {
        let root = scratch::case("extraction-checksum-publication");
        let archive = root.join("archive.rar");
        let payload = b"unique nonzero payload for corrupt checksum";
        let mut bytes = write_archive(
            &archive,
            version,
            &[
                (b"earlier.txt", b"valid earlier member"),
                (b"file.txt", payload),
            ],
        );
        let offset = bytes
            .windows(payload.len())
            .position(|window| window == payload)
            .unwrap();
        bytes[offset] ^= 1;
        fs::write(&archive, bytes).unwrap();
        let destination = root.join("out");
        fs::create_dir(&destination).unwrap();
        fs::write(destination.join("file.txt"), b"keep existing contents").unwrap();
        let result = extract(&archive, &destination, &[]);
        assert!(!result.status.success());
        assert_eq!(
            fs::read(destination.join("file.txt")).unwrap(),
            b"keep existing contents"
        );
        // Each member is published once verified, so a later failure keeps
        // the earlier one and leaves no staging behind.
        assert_eq!(
            fs::read(destination.join("earlier.txt")).unwrap(),
            b"valid earlier member"
        );
        assert_eq!(fs::read_dir(destination).unwrap().count(), 2);
    }
}

#[test]
fn later_integrity_failure_keeps_verified_redirection_over_empty_directory() {
    let root = scratch::case("extraction-redirection-directory-checksum");
    let archive_path = root.join("archive.rar");
    let fixture = rars::ArchiveReader::read_owned(
        include_bytes!("../../rars/tests/fixtures/rar50/wild/hardlink.rar").to_vec(),
    )
    .unwrap();
    let hardlink = fixture
        .members()
        .find(|member| member.meta.name == b"hardlink.txt")
        .unwrap();
    assert!(hardlink.supported_redirection().is_some());
    let payload = b"unique later payload with a corrupt checksum";
    let mut builder = Builder::new(ArchiveVersion::Rar50).store(true);
    builder
        .add_bytes(b"file.txt".to_vec(), b"test\n".to_vec(), None, None)
        .unwrap();
    builder.add_archive_redirection(&hardlink).unwrap();
    builder
        .add_bytes(b"later.txt".to_vec(), payload.to_vec(), None, None)
        .unwrap();
    let mut bytes = builder.to_bytes().unwrap();
    let parsed = rars::rar50::Archive::parse(&bytes).unwrap();
    assert_eq!(
        parsed
            .files()
            .map(|file| file.name.as_slice())
            .collect::<Vec<_>>(),
        vec![&b"file.txt"[..], &b"hardlink.txt"[..], &b"later.txt"[..]]
    );
    let later_range = parsed
        .files()
        .find(|file| file.name == b"later.txt")
        .unwrap()
        .block
        .data_range
        .clone();
    assert_eq!(&bytes[later_range.clone()], payload);
    fs::write(&archive_path, &bytes).unwrap();

    // Prove the framed archive and preserved hardlink are valid before making
    // only the later member fail. Its redirection precedes that member.
    let control = root.join("control");
    fs::create_dir_all(control.join("hardlink.txt")).unwrap();
    let result = extract(&archive_path, &control, &[]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(fs::read(control.join("hardlink.txt")).unwrap(), b"test\n");
    assert_eq!(fs::read(control.join("later.txt")).unwrap(), payload);

    bytes[later_range.start] ^= 1;
    fs::write(&archive_path, bytes).unwrap();
    let destination = root.join("out");
    let existing = destination.join("hardlink.txt");
    fs::create_dir_all(&existing).unwrap();
    let result = extract(&archive_path, &destination, &[]);
    assert!(!result.status.success());
    assert!(
        String::from_utf8_lossy(&result.stderr).contains("while verifying entry 'later.txt'")
            && String::from_utf8_lossy(&result.stderr).contains("checksum mismatch"),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    // The file and its redirection were verified before later.txt failed, so
    // both are published; the redirection replaces the empty directory.
    assert_eq!(fs::read(destination.join("file.txt")).unwrap(), b"test\n");
    assert_eq!(fs::read(&existing).unwrap(), b"test\n");
    assert!(!destination.join("later.txt").exists());
    assert_eq!(fs::read_dir(&destination).unwrap().count(), 2);
}

#[test]
fn limit_failure_preserves_existing_files_and_cleans_staging() {
    let root = scratch::case("extraction-limit-publication");
    let archive = root.join("archive.rar");
    write_archive(
        &archive,
        ArchiveVersion::Rar50,
        &[(b"file.txt", b"new contents")],
    );
    let destination = root.join("out");
    fs::create_dir(&destination).unwrap();
    fs::write(destination.join("file.txt"), b"keep existing contents").unwrap();
    let result = extract(&archive, &destination, &["--max-member-output-bytes", "1"]);
    assert!(!result.status.success());
    assert_eq!(
        fs::read(destination.join("file.txt")).unwrap(),
        b"keep existing contents"
    );
    assert_eq!(fs::read_dir(destination).unwrap().count(), 1);
}

#[test]
fn case_aliases_are_refused_on_insensitive_filesystems_and_kept_on_sensitive_ones() {
    let root = scratch::case("extraction-case-collision");
    let probe = root.join("CaseProbe");
    fs::write(&probe, []).unwrap();
    let insensitive = root.join("caseprobe").exists();
    fs::remove_file(probe).unwrap();
    let archive = root.join("archive.rar");
    write_archive(
        &archive,
        ArchiveVersion::Rar50,
        &[
            (b"A.txt", b"first contents"),
            (b"a.txt", b"second contents"),
        ],
    );
    let destination = root.join("out");
    let result = extract(&archive, &destination, &[]);
    if insensitive {
        assert!(!result.status.success());
        assert!(String::from_utf8_lossy(&result.stderr).contains("same output path"));
        // The first name was verified and published before its alias was refused.
        assert_eq!(
            fs::read(destination.join("A.txt")).unwrap(),
            b"first contents"
        );
        assert_eq!(fs::read_dir(destination).unwrap().count(), 1);
    } else {
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(
            fs::read(destination.join("A.txt")).unwrap(),
            b"first contents"
        );
        assert_eq!(
            fs::read(destination.join("a.txt")).unwrap(),
            b"second contents"
        );
    }
}

#[cfg(unix)]
#[test]
fn in_place_overwrites_the_existing_file_itself() {
    use std::os::unix::fs::MetadataExt;
    let root = scratch::case("extraction-in-place-inode");
    let archive = root.join("archive.rar");
    write_archive(&archive, ArchiveVersion::Rar50, &[(b"file.txt", b"new")]);
    let destination = root.join("out");
    fs::create_dir(&destination).unwrap();
    fs::write(destination.join("file.txt"), b"a longer old file").unwrap();
    let inode = fs::metadata(destination.join("file.txt")).unwrap().ino();

    let result = extract(&archive, &destination, &["--in-place"]);

    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(fs::read(destination.join("file.txt")).unwrap(), b"new");
    assert_eq!(
        fs::metadata(destination.join("file.txt")).unwrap().ino(),
        inode
    );
}

#[cfg(unix)]
#[test]
fn in_place_needs_no_write_permission_on_the_directory() {
    use std::os::unix::fs::PermissionsExt;
    let root = scratch::case("extraction-in-place-readonly");
    let archive = root.join("archive.rar");
    write_archive(&archive, ArchiveVersion::Rar50, &[(b"file.txt", b"new")]);
    let destination = root.join("out");
    fs::create_dir(&destination).unwrap();
    fs::write(destination.join("file.txt"), b"old").unwrap();
    fs::set_permissions(&destination, fs::Permissions::from_mode(0o555)).unwrap();
    if fs::write(destination.join("probe"), b"").is_ok() {
        return; // Permissions don't bind root.
    }

    let staged = extract(&archive, &destination, &[]);
    let in_place = extract(&archive, &destination, &["--in-place"]);
    fs::set_permissions(&destination, fs::Permissions::from_mode(0o755)).unwrap();

    assert!(!staged.status.success());
    assert!(
        in_place.status.success(),
        "{}",
        String::from_utf8_lossy(&in_place.stderr)
    );
    assert_eq!(fs::read(destination.join("file.txt")).unwrap(), b"new");
}

#[cfg(unix)]
#[test]
fn in_place_refuses_a_hard_link_or_fifo_at_the_destination() {
    for kind in ["hard link", "fifo"] {
        let root = scratch::case("extraction-in-place-refusal");
        let archive = root.join("archive.rar");
        write_archive(&archive, ArchiveVersion::Rar50, &[(b"file.txt", b"new")]);
        let destination = root.join("out");
        fs::create_dir(&destination).unwrap();
        let outside = root.join("outside.txt");
        fs::write(&outside, b"outside").unwrap();
        let target = destination.join("file.txt");
        if kind == "hard link" {
            fs::hard_link(&outside, &target).unwrap();
        } else {
            assert!(Command::new("mkfifo")
                .arg(&target)
                .status()
                .unwrap()
                .success());
        }

        let result = extract(&archive, &destination, &["--in-place"]);

        assert!(!result.status.success(), "{kind}");
        assert_eq!(fs::read(&outside).unwrap(), b"outside");
    }
}

/// What one `x` run left: its exit code, its output with the destination
/// written as `OUT`, and every entry under the destination with its contents.
type Extracted = (Option<i32>, String, String, Vec<(String, Vec<u8>)>);

fn extract_tree(archive: &Path, destination: &Path, args: &[&str]) -> Extracted {
    let result = Command::new(env!("CARGO_BIN_EXE_rars"))
        .arg("x")
        .args(args)
        .arg(archive)
        .arg(destination)
        .output()
        .unwrap();
    let mut files = Vec::new();
    let mut pending = vec![destination.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory).unwrap() {
            let path = entry.unwrap().path();
            let relative = path.strip_prefix(destination).unwrap();
            let relative = relative.to_string_lossy().replace('\\', "/");
            if path.is_dir() {
                files.push((format!("{relative}/"), Vec::new()));
                pending.push(path);
            } else {
                files.push((relative, fs::read(&path).unwrap()));
            }
        }
    }
    files.sort();
    let shown = destination.to_string_lossy();
    let text = |bytes: &[u8]| String::from_utf8_lossy(bytes).replace(&*shown, "OUT");
    (
        result.status.code(),
        text(&result.stdout),
        text(&result.stderr),
        files,
    )
}

/// Members over the buffered limit used, with small ones among them, for the
/// tests of members decoded and written side by side.
fn large_members() -> (Vec<u8>, Vec<(String, Vec<u8>)>) {
    let mut builder = Builder::new(ArchiveVersion::Rar50);
    let mut sources = Vec::new();
    for index in 0..10u32 {
        let name = format!("dir{}/member{index}.bin", index % 3);
        let len = if index % 4 == 3 {
            200 + index
        } else {
            30_000 + 1_000 * index
        };
        let data: Vec<u8> = (0..len)
            .map(|n| (n * 7 / (index + 3) + index * 11) as u8)
            .collect();
        builder
            .add_bytes(name.clone().into_bytes(), data.clone(), None, None)
            .unwrap();
        sources.push((name, data));
    }
    (builder.to_bytes().unwrap(), sources)
}

/// The entries `sources` extract to, without those left out.
fn expected_files(sources: &[(String, Vec<u8>)], left_out: &[&str]) -> Vec<(String, Vec<u8>)> {
    let mut files: Vec<_> = sources
        .iter()
        .filter(|(name, _)| !left_out.contains(&name.as_str()))
        .cloned()
        .collect();
    for directory in ["dir0/", "dir1/", "dir2/"] {
        if files.iter().any(|(name, _)| name.starts_with(directory)) {
            files.push((directory.to_string(), Vec::new()));
        }
    }
    files.sort();
    files
}

/// Runs `x` at one, two and eight threads, and checks every run reports,
/// exits and leaves exactly what the one-thread run does.
fn extract_at_thread_counts(
    archive: &Path,
    root: &Path,
    args: &[&str],
    prepare: impl Fn(&Path),
) -> Extracted {
    let mut runs = Vec::new();
    for threads in ["1", "2", "8"] {
        let destination = root.join(format!("out-{threads}"));
        prepare(&destination);
        let mut args = args.to_vec();
        args.extend([
            "--threads",
            threads,
            "--rar50-buffered-decode-limit",
            "4096",
        ]);
        runs.push((threads, extract_tree(archive, &destination, &args)));
    }
    let (_, one) = runs.remove(0);
    for (threads, run) in runs {
        assert_eq!(run, one, "threads={threads}");
    }
    one
}

/// Large members decode and are written side by side, and the members after
/// one are opened before it fails its checksum. It must still never be
/// published, and the run must report and exit exactly as at one thread.
#[test]
fn a_failing_member_among_concurrent_large_members_is_never_published() {
    let root = scratch::case("extraction-concurrent-checksum");
    let archive = root.join("archive.rar");
    let (mut bytes, sources) = large_members();
    let parsed = rars::rar50::Archive::parse(&bytes).unwrap();
    let failing = parsed
        .files()
        .find(|file| file.name == b"dir1/member4.bin")
        .unwrap()
        .block
        .data_range
        .clone();
    bytes[(failing.start + failing.end) / 2] ^= 0x55;
    fs::write(&archive, &bytes).unwrap();

    let run = extract_at_thread_counts(&archive, &root, &[], |_| {});
    assert_ne!(run.0, Some(0), "{}", run.2);
    assert!(run.2.contains("member4.bin"), "{}", run.2);
    assert!(!run.1.contains("member4.bin"), "{}", run.1);
    assert_eq!(run.3, expected_files(&sources, &["dir1/member4.bin"]));
}

/// A member whose output cannot be opened, among large members already
/// decoding, ends the run as it does at one thread: the members before it
/// are published, the existing file is kept, and none after it is published.
#[test]
fn a_refused_output_among_concurrent_large_members_ends_the_run_there() {
    let root = scratch::case("extraction-concurrent-refusal");
    let archive = root.join("archive.rar");
    let (bytes, sources) = large_members();
    fs::write(&archive, &bytes).unwrap();

    let run = extract_at_thread_counts(&archive, &root, &["--overwrite=never"], |out| {
        fs::create_dir_all(out.join("dir2")).unwrap();
        fs::write(out.join("dir2/member5.bin"), b"keep me").unwrap();
    });
    assert_ne!(run.0, Some(0), "{}", run.2);
    let mut expected = expected_files(&sources[..5], &[]);
    expected.push(("dir2/member5.bin".to_string(), b"keep me".to_vec()));
    expected.sort();
    assert_eq!(run.3, expected, "{}", run.2);
}

/// Files are created, written, given their times and modes and closed where
/// they are written, empty ones included, and keep all of it once published.
#[test]
fn files_written_on_workers_keep_their_contents_times_and_modes() {
    let root = scratch::case("extraction-worker-metadata");
    let archive = root.join("archive.rar");
    let seconds = 1_600_000_000;
    let mut builder = Builder::new(ArchiveVersion::Rar50);
    let mut sources = Vec::new();
    for index in 0..12u32 {
        let name = format!("dir{}/file{index}.txt", index % 3);
        let data = if index % 4 == 0 {
            Vec::new()
        } else {
            format!("contents of member {index}; ")
                .repeat(index as usize * 50)
                .into_bytes()
        };
        builder
            .add_bytes(
                name.clone().into_bytes(),
                data.clone(),
                Some(rars::Timestamp::from_unix_seconds(seconds)),
                Some(0o100640),
            )
            .unwrap();
        sources.push((name, data));
    }
    fs::write(&archive, builder.to_bytes().unwrap()).unwrap();

    let run = extract_at_thread_counts(&archive, &root, &[], |_| {});
    assert_eq!(run.0, Some(0), "{}", run.2);
    assert_eq!(run.3, expected_files(&sources, &[]));
    let modified = std::time::UNIX_EPOCH + std::time::Duration::from_secs(seconds as u64);
    for threads in ["1", "2", "8"] {
        for (name, _) in &sources {
            let path = root.join(format!("out-{threads}")).join(name);
            let metadata = fs::metadata(&path).unwrap();
            assert_eq!(metadata.modified().unwrap(), modified, "{}", path.display());
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(
                    metadata.permissions().mode() & 0o777,
                    0o640,
                    "{}",
                    path.display()
                );
            }
        }
    }
}

/// In place, files take their times and modes whether they were created or
/// were there already, with other contents and another mode.
#[cfg(unix)]
#[test]
fn files_written_in_place_keep_their_times_and_modes() {
    use std::os::unix::fs::PermissionsExt;
    let root = scratch::case("extraction-in-place-metadata");
    let archive = root.join("archive.rar");
    let seconds = 1_600_000_000;
    let mut builder = Builder::new(ArchiveVersion::Rar50);
    let mut sources = Vec::new();
    for index in 0..6u32 {
        let name = format!("dir{}/file{index}.txt", index % 2);
        let data = format!("member {index}").into_bytes();
        let mode = if index % 3 == 0 { 0o751 } else { 0o640 };
        builder
            .add_bytes(
                name.clone().into_bytes(),
                data.clone(),
                Some(rars::Timestamp::from_unix_seconds(seconds)),
                Some(0o100000 | mode),
            )
            .unwrap();
        sources.push((name, data, mode));
    }
    fs::write(&archive, builder.to_bytes().unwrap()).unwrap();
    let destination = root.join("out");
    let modified = std::time::UNIX_EPOCH + std::time::Duration::from_secs(seconds as u64);
    for overwrite in ["--overwrite=never", "--overwrite=always"] {
        if overwrite == "--overwrite=always" {
            for (name, _, _) in &sources {
                let path = destination.join(name);
                fs::write(&path, b"a longer file that was there before").unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            }
        }
        let result = Command::new(env!("CARGO_BIN_EXE_rars"))
            .args(["x", "--in-place", overwrite])
            .arg(&archive)
            .arg(&destination)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{overwrite}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        for (name, data, mode) in &sources {
            let path = destination.join(name);
            assert_eq!(&fs::read(&path).unwrap(), data, "{overwrite} {name}");
            let metadata = fs::metadata(&path).unwrap();
            assert_eq!(metadata.modified().unwrap(), modified, "{overwrite} {name}");
            assert_eq!(
                metadata.permissions().mode() & 0o777,
                *mode,
                "{overwrite} {name}"
            );
        }
    }
}

/// A file member landing on a directory an earlier member's path made is
/// refused as another member's output, whether the earlier member was
/// published before it opened or only after, so every thread count reports
/// it alike; the earlier member is kept and none after it is published.
/// Where outputs are checked by path instead, a member that opens after
/// the directory was made still finds only an existing file.
#[cfg(unix)]
#[test]
fn a_file_landing_on_an_earlier_members_directory_is_refused_alike() {
    for overwrite in ["--overwrite=never", "--overwrite=always"] {
        let root = scratch::case("extraction-file-over-made-directory");
        let archive = root.join("archive.rar");
        write_archive(
            &archive,
            ArchiveVersion::Rar50,
            &[
                (b"a/b/c", b"inner"),
                (b"a/b", b"outer"),
                (b"z.txt", b"after"),
            ],
        );
        let run = extract_at_thread_counts(&archive, &root, &[overwrite], |_| {});
        assert_ne!(run.0, Some(0), "{overwrite}: {}", run.2);
        assert!(
            run.2
                .contains("multiple archive entries map to the same output path"),
            "{overwrite}: {}",
            run.2
        );
        assert_eq!(
            run.3,
            [
                ("a/".to_string(), Vec::new()),
                ("a/b/".to_string(), Vec::new()),
                ("a/b/c".to_string(), b"inner".to_vec()),
            ],
            "{overwrite}: {}",
            run.2
        );
    }
}

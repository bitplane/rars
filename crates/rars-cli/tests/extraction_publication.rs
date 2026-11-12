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
            && String::from_utf8_lossy(&result.stderr).contains("hash mismatch"),
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

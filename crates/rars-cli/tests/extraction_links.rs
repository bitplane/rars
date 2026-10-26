#[path = "support/scratch.rs"]
mod scratch;
use rars::{ArchiveVersion, Builder};
use std::{
    fs,
    path::Path,
    process::{Command, Output},
};

fn extract(archive: &Path, out: &Path, extra: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rars"))
        .arg("extract")
        .args(extra)
        .arg(archive)
        .arg(out)
        .output()
        .unwrap()
}
fn write_archive(
    path: &Path,
    version: ArchiveVersion,
    store: bool,
    solid: bool,
    target: &[u8],
) -> Vec<u8> {
    let mut builder = Builder::new(version).store(store).solid(solid);
    builder
        .add_bytes(
            b"real.txt".to_vec(),
            b"hello\n".to_vec(),
            Some(1_700_000_000),
            Some(0o640),
        )
        .unwrap();
    builder
        .add_unix_symlink(
            b"link-to-real.txt".to_vec(),
            target.to_vec(),
            false,
            Some(1_600_000_000),
            Some(0o777),
        )
        .unwrap();
    builder
        .add_bytes(b"after".to_vec(), b"hello\n".repeat(100), None, None)
        .unwrap();
    let bytes = builder.to_bytes().unwrap();
    fs::write(path, &bytes).unwrap();
    bytes
}

#[cfg(unix)]
#[test]
fn extracts_links_consistently_across_formats_without_chmod_through_links() {
    use std::os::unix::fs::PermissionsExt;
    for version in [
        ArchiveVersion::Rar20,
        ArchiveVersion::Rar40,
        ArchiveVersion::Rar50,
    ] {
        for (store, solid) in [(true, false), (false, false), (false, true)] {
            let root = scratch::case("common-link-extraction");
            let archive = root.join("links.rar");
            write_archive(&archive, version, store, solid, b"real.txt");
            let out = root.join("out");
            let result = extract(&archive, &out, &[]);
            assert!(
                result.status.success(),
                "{version:?} {store} {solid}: {}",
                String::from_utf8_lossy(&result.stderr)
            );
            assert_eq!(
                fs::read_link(out.join("link-to-real.txt")).unwrap(),
                Path::new("real.txt")
            );
            assert_eq!(fs::read(out.join("link-to-real.txt")).unwrap(), b"hello\n");
            assert_eq!(fs::read(out.join("after")).unwrap(), b"hello\n".repeat(100));
            assert_eq!(
                fs::metadata(out.join("real.txt"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o640
            );
            assert_eq!(fs::read_dir(&out).unwrap().count(), 3);
        }
    }
}

#[cfg(unix)]
#[test]
fn native_legacy_targets_ignore_codepages_and_preserve_backslashes() {
    use std::os::unix::ffi::OsStrExt;
    let root = scratch::case("legacy-link-target-bytes");
    let archive = root.join("links.rar");
    let target = b"native-\xff\\name";
    write_archive(&archive, ArchiveVersion::Rar40, true, false, target);
    let out = root.join("out");
    let result = extract(&archive, &out, &["--legacy-name-encoding=cp850"]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        fs::read_link(out.join("link-to-real.txt"))
            .unwrap()
            .as_os_str()
            .as_bytes(),
        target
    );
}

#[test]
fn unsafe_or_corrupt_link_targets_keep_verified_predecessors_and_existing_destinations() {
    for case in 0..4 {
        let root = scratch::case("legacy-link-refusal");
        let archive = root.join("links.rar");
        let target = match case {
            0 => b"../escape".as_slice(),
            1 => b"/absolute",
            _ => b"unique-target",
        };
        let mut bytes = write_archive(&archive, ArchiveVersion::Rar40, true, false, target);
        if case >= 2 {
            let offset = bytes
                .windows(target.len())
                .position(|v| v == target)
                .unwrap();
            bytes[offset] ^= 1;
            if case == 3 {
                // NUL with a valid payload CRC tests validation after verification.
                bytes[offset] = 0;
                let mut at = 7;
                while at < bytes.len() {
                    let kind = bytes[at + 2];
                    let flags = u16::from_le_bytes(bytes[at + 3..at + 5].try_into().unwrap());
                    let size =
                        u16::from_le_bytes(bytes[at + 5..at + 7].try_into().unwrap()) as usize;
                    let packed = if flags & 0x8000 != 0 {
                        u32::from_le_bytes(bytes[at + 7..at + 11].try_into().unwrap()) as usize
                    } else {
                        0
                    };
                    if kind == 0x74 && at + size == offset {
                        let crc = rars::crc32::crc32(&bytes[offset..offset + target.len()]);
                        bytes[at + 16..at + 20].copy_from_slice(&crc.to_le_bytes());
                        let header = rars::crc32::crc32(&bytes[at + 2..at + size]) as u16;
                        bytes[at..at + 2].copy_from_slice(&header.to_le_bytes());
                        break;
                    }
                    at += size + packed;
                }
            }
            fs::write(&archive, bytes).unwrap();
        }
        let out = root.join("out");
        fs::create_dir(&out).unwrap();
        fs::write(out.join("link-to-real.txt"), b"keep").unwrap();
        let result = extract(&archive, &out, &["--overwrite=always"]);
        assert!(!result.status.success(), "case {case}");
        assert_eq!(fs::read(out.join("real.txt")).unwrap(), b"hello\n");
        assert_eq!(fs::read(out.join("link-to-real.txt")).unwrap(), b"keep");
        assert!(!out.join("after").exists());
        assert_eq!(fs::read_dir(out).unwrap().count(), 2);
    }
}

#[cfg(unix)]
#[test]
fn legacy_link_overwrite_and_colliding_paths_use_shared_publication_rules() {
    let root = scratch::case("legacy-link-overwrite");
    let archive = root.join("links.rar");
    write_archive(&archive, ArchiveVersion::Rar40, true, false, b"real.txt");
    for directory in [false, true] {
        let out = root.join(if directory { "dir" } else { "file" });
        fs::create_dir(&out).unwrap();
        if directory {
            fs::create_dir(out.join("link-to-real.txt")).unwrap();
        } else {
            fs::write(out.join("link-to-real.txt"), b"keep").unwrap();
        }
        let refused = extract(&archive, &out, &[]);
        assert!(!refused.status.success());
        assert!(!fs::symlink_metadata(out.join("link-to-real.txt"))
            .unwrap()
            .file_type()
            .is_symlink());
        let replaced = extract(&archive, &out, &["--overwrite=always"]);
        assert!(
            replaced.status.success(),
            "{}",
            String::from_utf8_lossy(&replaced.stderr)
        );
        assert_eq!(
            fs::read_link(out.join("link-to-real.txt")).unwrap(),
            Path::new("real.txt")
        );
    }
    let mut builder = Builder::new(ArchiveVersion::Rar40).store(true);
    builder
        .add_bytes(b"same".to_vec(), b"keep".to_vec(), None, None)
        .unwrap();
    builder
        .add_unix_symlink(b"./same".to_vec(), b"target".to_vec(), false, None, None)
        .unwrap();
    fs::write(&archive, builder.to_bytes().unwrap()).unwrap();
    let out = root.join("collision");
    let result = extract(&archive, &out, &["--overwrite=always"]);
    assert!(!result.status.success());
    assert_eq!(fs::read(out.join("same")).unwrap(), b"keep");
}

#[cfg(unix)]
#[test]
fn legacy_link_result_matches_unrar_when_available() {
    let root = scratch::case("legacy-link-unrar");
    let archive = root.join("links.rar");
    write_archive(&archive, ArchiveVersion::Rar40, true, false, b"real.txt");
    let reference = root.join("reference");
    fs::create_dir(&reference).unwrap();
    let unrar = match Command::new("unrar")
        .args(["x", "-idq"])
        .arg(&archive)
        .arg(format!("{}/", reference.display()))
        .output()
    {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
        result => result.unwrap(),
    };
    assert!(
        unrar.status.success(),
        "{}",
        String::from_utf8_lossy(&unrar.stderr)
    );
    let out = root.join("out");
    assert!(extract(&archive, &out, &[]).status.success());
    assert_eq!(
        fs::read_link(out.join("link-to-real.txt")).unwrap(),
        fs::read_link(reference.join("link-to-real.txt")).unwrap()
    );
}

#[cfg(windows)]
#[test]
fn legacy_symlink_creation_succeeds_or_reports_missing_privilege_without_publishing_payload() {
    let root = scratch::case("legacy-link-windows");
    let archive = root.join("links.rar");
    write_archive(&archive, ArchiveVersion::Rar40, true, false, b"real.txt");
    let out = root.join("out");
    let result = extract(&archive, &out, &[]);
    if result.status.success() {
        assert!(fs::symlink_metadata(out.join("link-to-real.txt"))
            .unwrap()
            .file_type()
            .is_symlink());
    } else {
        assert!(
            String::from_utf8_lossy(&result.stderr).contains("os error 1314"),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(fs::symlink_metadata(out.join("link-to-real.txt")).is_err());
        assert_eq!(fs::read(out.join("real.txt")).unwrap(), b"hello\n");
    }
}

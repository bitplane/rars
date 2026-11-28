#![cfg(feature = "write")]
//! `Archive::extract_to_dir` and `extract_volumes_to_dir` against the
//! expectations the Python binding's `extractall` tests hold it to.

use rars::{
    Archive, ArchiveReadOptions, ArchiveReader, ArchiveVersion, Builder, ErrorKind,
    ExtractDirOptions, ExtractionErrorAction, OverwritePolicy, Timestamp,
};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::SystemTime;

#[path = "support/scratch.rs"]
mod scratch;
#[path = "support/vint.rs"]
mod vint;
use vint::read_vint;

const DIR_TIME: i64 = 1_600_000_000;
const FILE_TIME: i64 = 1_650_000_000;

fn read(bytes: Vec<u8>) -> Archive {
    ArchiveReader::read_owned(bytes).unwrap()
}

fn time(seconds: i64) -> Option<Timestamp> {
    Some(Timestamp::from_unix_seconds(seconds))
}

fn modified(path: &Path) -> SystemTime {
    fs::metadata(path).unwrap().modified().unwrap()
}

/// The time the archive records for `name`, as extraction should restore it.
fn stored_time(archive: &Archive, name: &[u8]) -> SystemTime {
    let member = archive
        .members()
        .find(|member| member.meta.name == name)
        .unwrap();
    SystemTime::try_from(member.meta.modification_time().unwrap()).unwrap()
}

/// Every path under `root`, relative to it, without following links.
fn tree(root: &Path) -> BTreeSet<PathBuf> {
    fn walk(root: &Path, dir: &Path, found: &mut BTreeSet<PathBuf>) {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            found.insert(path.strip_prefix(root).unwrap().to_path_buf());
            if fs::symlink_metadata(&path).unwrap().is_dir() {
                walk(root, &path, found);
            }
        }
    }
    let mut found = BTreeSet::new();
    walk(root, root, &mut found);
    found
}

fn paths(names: &[&str]) -> BTreeSet<PathBuf> {
    names.iter().map(PathBuf::from).collect()
}

/// Swaps a RAR 5 member name for one of the same length and repairs the
/// header CRC, giving a well-formed archive the builder would refuse to make.
fn rewrite_rar5_name(archive: &[u8], placeholder: &[u8], replacement: &[u8]) -> Vec<u8> {
    assert_eq!(placeholder.len(), replacement.len());
    let mut patched = archive.to_vec();
    let mut at = 8;
    while at + 4 < archive.len() {
        let body_at = at + 4;
        let mut cursor = body_at;
        let size = read_vint(archive, &mut cursor);
        let body_end = cursor + size as usize;
        let kind = read_vint(archive, &mut cursor);
        let flags = read_vint(archive, &mut cursor);
        if flags & 1 != 0 {
            read_vint(archive, &mut cursor);
        }
        let data_size = if flags & 2 != 0 {
            read_vint(archive, &mut cursor) as usize
        } else {
            0
        };
        if let Some(found) = archive[body_at..body_end]
            .windows(placeholder.len())
            .position(|window| window == placeholder)
        {
            let found = body_at + found;
            patched[found..found + placeholder.len()].copy_from_slice(replacement);
            let crc = rars::crc32::crc32(&patched[body_at..body_end]);
            patched[at..at + 4].copy_from_slice(&crc.to_le_bytes());
            return patched;
        }
        if kind == 5 {
            break;
        }
        at = body_end + data_size;
    }
    panic!("placeholder is not inside any block header");
}

/// A RAR 5 archive with directories, files, symbolic links, Unix and Windows
/// attributes, and a member named `../escape.txt` between the others.
fn mixed_rar5() -> Vec<u8> {
    let mut builder = Builder::new(ArchiveVersion::Rar50).store(true);
    builder
        .add_directory(b"unix".to_vec(), time(DIR_TIME), Some(0o755))
        .unwrap();
    builder
        .add_bytes(
            b"unix/file.txt".to_vec(),
            b"unix file".to_vec(),
            time(FILE_TIME),
            Some(0o100644),
        )
        .unwrap();
    builder
        .add_unix_symlink(
            b"unix/link.txt".to_vec(),
            b"file.txt".to_vec(),
            false,
            None,
            None,
        )
        .unwrap();
    builder
        .add_bytes(
            b"ppppppppppppp".to_vec(),
            b"owned".to_vec(),
            time(FILE_TIME),
            None,
        )
        .unwrap();
    builder
        .add_directory(b"windows".to_vec(), time(DIR_TIME), None)
        .unwrap();
    builder.set_dos_attributes(b"windows", 0x10 | 0x02).unwrap();
    builder
        .add_bytes(
            b"windows/readonly.txt".to_vec(),
            b"windows file".to_vec(),
            time(FILE_TIME),
            None,
        )
        .unwrap();
    builder
        .set_dos_attributes(b"windows/readonly.txt", 0x20 | 0x01)
        .unwrap();
    builder
        .add_unix_symlink(
            b"escape.txt".to_vec(),
            b"../outside.txt".to_vec(),
            false,
            None,
            None,
        )
        .unwrap();
    rewrite_rar5_name(
        &builder.to_bytes().unwrap(),
        b"ppppppppppppp",
        b"../escape.txt",
    )
}

/// A member error handler that carries on, recording each member it saw.
fn recorded(
    seen: &Mutex<Vec<(Vec<u8>, ErrorKind)>>,
) -> impl Fn(&rars::ArchiveMember, &rars::Error) -> rars::Result<ExtractionErrorAction> + Sync + '_
{
    move |member, error| {
        seen.lock()
            .unwrap()
            .push((member.meta.name.clone(), error.kind()));
        Ok(ExtractionErrorAction::Continue)
    }
}

#[cfg(unix)]
#[test]
fn mixed_archive_extracts_as_extractall_does() {
    let root = scratch::case("extract-to-dir-mixed");
    let out = root.join("out");
    let archive = read(mixed_rar5());
    let seen = Mutex::new(Vec::new());
    let handler = recorded(&seen);
    let options = ExtractDirOptions::new()
        .with_read_options(ArchiveReadOptions::new().with_member_error_handler(&handler));

    let extracted = archive.extract_to_dir(&out, &options).unwrap();

    // The member climbing out is refused and gone past; nothing escapes.
    assert_eq!(
        *seen.lock().unwrap(),
        vec![(b"../escape.txt".to_vec(), ErrorKind::UnsafePath)]
    );
    assert!(tree(&root).iter().all(|path| path.starts_with("out")));
    assert_eq!(
        tree(&out),
        paths(&[
            "unix",
            "unix/file.txt",
            "unix/link.txt",
            "windows",
            "windows/readonly.txt",
        ])
    );
    assert_eq!(
        extracted.paths,
        [
            "unix",
            "unix/file.txt",
            "unix/link.txt",
            "windows",
            "windows/readonly.txt",
        ]
        .map(|name| out.join(name))
    );
    assert_eq!(fs::read(out.join("unix/file.txt")).unwrap(), b"unix file");
    assert_eq!(
        fs::read(out.join("windows/readonly.txt")).unwrap(),
        b"windows file"
    );

    // A link that stays inside is created; one that would lead outside is
    // left out and reported, as the binding warns of it.
    assert_eq!(
        fs::read_link(out.join("unix/link.txt")).unwrap(),
        Path::new("file.txt")
    );
    assert_eq!(fs::read(out.join("unix/link.txt")).unwrap(), b"unix file");
    assert_eq!(extracted.skipped_links.len(), 1);
    assert_eq!(extracted.skipped_links[0].name, b"escape.txt");
    assert_eq!(extracted.skipped_links[0].target, b"../outside.txt");

    assert!(fs::metadata(out.join("windows/readonly.txt"))
        .unwrap()
        .permissions()
        .readonly());

    for name in ["unix", "unix/file.txt", "windows", "windows/readonly.txt"] {
        assert_eq!(
            modified(&out.join(name)),
            stored_time(&archive, name.as_bytes()),
            "{name}"
        );
    }
}

#[test]
fn mixed_archive_without_a_handler_stops_at_the_unsafe_member() {
    let root = scratch::case("extract-to-dir-mixed-stops");
    let out = root.join("out");
    let archive = read(mixed_rar5());

    let error = archive
        .extract_to_dir(&out, &ExtractDirOptions::default())
        .unwrap_err();

    assert_eq!(error.kind(), ErrorKind::UnsafePath);
    // The members before it are in place; nothing reached outside.
    let found = tree(&out);
    assert!(found.contains(Path::new("unix/file.txt")), "{found:?}");
    assert!(!found.iter().any(|path| path.starts_with("windows")));
    assert_eq!(tree(&root).len(), found.len() + 1);
}

#[test]
fn hostile_member_names_are_refused() {
    let root = scratch::case("extract-to-dir-hostile");
    for (index, name) in [
        b"../escape.txt".as_slice(),
        b"a/../../escape.txt",
        b"..\\escape.txt",
        b"/etc/passwd",
        b"C:\\windows\\x",
        b"with\0nul.txt",
    ]
    .into_iter()
    .enumerate()
    {
        let placeholder = vec![b'p'; name.len()];
        let mut builder = Builder::new(ArchiveVersion::Rar50).store(true);
        builder
            .add_bytes(placeholder.clone(), b"owned\n".to_vec(), None, None)
            .unwrap();
        let archive = read(rewrite_rar5_name(
            &builder.to_bytes().unwrap(),
            &placeholder,
            name,
        ));
        let case = root.join(index.to_string());
        let out = case.join("out");
        fs::create_dir_all(&out).unwrap();

        let error = archive
            .extract_to_dir(&out, &ExtractDirOptions::default())
            .unwrap_err();

        let label = String::from_utf8_lossy(name);
        assert_eq!(error.kind(), ErrorKind::UnsafePath, "{label}: {error}");
        assert_eq!(tree(&out), BTreeSet::new(), "{label}");
        assert_eq!(tree(&case), paths(&["out"]), "{label}");
    }
}

#[cfg(unix)]
#[test]
fn symlinks_already_in_the_directory_are_not_followed() {
    let root = scratch::case("extract-to-dir-planted");
    let outside = root.join("outside");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("file.txt"), b"keep").unwrap();
    let out = root.join("out");
    fs::create_dir(&out).unwrap();
    std::os::unix::fs::symlink(&outside, out.join("sub")).unwrap();
    std::os::unix::fs::symlink(outside.join("file.txt"), out.join("member.txt")).unwrap();
    let mut builder = Builder::new(ArchiveVersion::Rar50);
    builder
        .add_bytes(b"sub/file.txt".to_vec(), b"owned".to_vec(), None, None)
        .unwrap();
    let through_dir = read(builder.to_bytes().unwrap());
    let mut builder = Builder::new(ArchiveVersion::Rar50);
    builder
        .add_bytes(b"member.txt".to_vec(), b"owned".to_vec(), None, None)
        .unwrap();
    let through_file = read(builder.to_bytes().unwrap());
    let overwrite = ExtractDirOptions::new().with_overwrite(OverwritePolicy::Always);

    let error = through_dir.extract_to_dir(&out, &overwrite).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::UnsafePath);
    let error = through_file.extract_to_dir(&out, &overwrite).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::UnsafePath);

    assert_eq!(fs::read(outside.join("file.txt")).unwrap(), b"keep");
}

#[test]
fn file_and_directory_times_are_restored() {
    let root = scratch::case("extract-to-dir-times");
    for format in [
        ArchiveVersion::Rar13,
        ArchiveVersion::Rar15,
        ArchiveVersion::Rar20,
        ArchiveVersion::Rar29,
        ArchiveVersion::Rar40,
        ArchiveVersion::Rar50,
    ] {
        let mut builder = Builder::new(format);
        builder
            .add_directory(b"dir".to_vec(), time(DIR_TIME), None)
            .unwrap();
        builder
            .add_bytes(
                b"dir/file.txt".to_vec(),
                b"payload".to_vec(),
                time(FILE_TIME),
                None,
            )
            .unwrap();
        let archive = read(builder.to_bytes().unwrap());
        let out = root.join(format.to_string());

        archive
            .extract_to_dir(&out, &ExtractDirOptions::default())
            .unwrap();

        assert_eq!(modified(&out.join("dir")), stored_time(&archive, b"dir"));
        assert_eq!(
            modified(&out.join("dir/file.txt")),
            stored_time(&archive, b"dir/file.txt")
        );
    }
}

#[test]
fn rar5_times_keep_their_fraction() {
    let root = scratch::case("extract-to-dir-fraction");
    let stored = Timestamp::new(1_700_000_000, 123_456_700).unwrap();
    let mut builder = Builder::new(ArchiveVersion::Rar50);
    builder
        .add_bytes(
            b"file.txt".to_vec(),
            b"payload".to_vec(),
            Some(stored),
            None,
        )
        .unwrap();

    read(builder.to_bytes().unwrap())
        .extract_to_dir(&root, &ExtractDirOptions::default())
        .unwrap();

    assert_eq!(
        modified(&root.join("file.txt")),
        SystemTime::try_from(stored).unwrap()
    );
}

#[test]
fn times_are_left_alone_when_asked() {
    let root = scratch::case("extract-to-dir-no-times");
    let mut builder = Builder::new(ArchiveVersion::Rar50);
    builder
        .add_bytes(
            b"file.txt".to_vec(),
            b"payload".to_vec(),
            time(DIR_TIME),
            None,
        )
        .unwrap();
    let options = ExtractDirOptions::new().with_restore_times(false);

    read(builder.to_bytes().unwrap())
        .extract_to_dir(&root, &options)
        .unwrap();

    assert!(
        modified(&root.join("file.txt"))
            > SystemTime::try_from(Timestamp::from_unix_seconds(DIR_TIME)).unwrap()
    );
}

#[test]
fn legacy_names_decode_with_the_read_options_encoding() {
    let root = scratch::case("extract-to-dir-legacy-encoding");
    for format in [
        ArchiveVersion::Rar13,
        ArchiveVersion::Rar15,
        ArchiveVersion::Rar29,
        ArchiveVersion::Rar40,
    ] {
        let mut builder = Builder::new(format).store(true);
        builder
            .add_bytes(b"caf\x82.txt".to_vec(), b"payload".to_vec(), None, None)
            .unwrap();
        let archive = read(builder.to_bytes().unwrap());
        let out = root.join(format.to_string());
        let mut read_options = ArchiveReadOptions::new();
        read_options.legacy_name_encoding = Some(rars::filename::LegacyNameEncoding::Cp850);
        let options = ExtractDirOptions::new().with_read_options(read_options);

        archive.extract_to_dir(&out, &options).unwrap();

        assert_eq!(fs::read(out.join("café.txt")).unwrap(), b"payload");
    }
}

#[test]
fn modern_unicode_names_are_not_reinterpreted() {
    let root = scratch::case("extract-to-dir-unicode");
    let mut builder = Builder::new(ArchiveVersion::Rar50);
    builder
        .add_bytes("café.txt".as_bytes().to_vec(), b"x".to_vec(), None, None)
        .unwrap();
    let mut read_options = ArchiveReadOptions::new();
    read_options.legacy_name_encoding = Some(rars::filename::LegacyNameEncoding::Cp850);

    read(builder.to_bytes().unwrap())
        .extract_to_dir(
            &root,
            &ExtractDirOptions::new().with_read_options(read_options),
        )
        .unwrap();

    assert_eq!(fs::read(root.join("café.txt")).unwrap(), b"x");
}

/// Without an encoding, a legacy name's bytes are the file name, where the
/// filesystem takes them.
#[cfg(unix)]
#[test]
fn legacy_names_keep_their_bytes_by_default() {
    use std::os::unix::ffi::OsStrExt;
    let root = scratch::case("extract-to-dir-legacy-bytes");
    let mut builder = Builder::new(ArchiveVersion::Rar29).store(true);
    builder
        .add_bytes(b"legacy-\xff".to_vec(), b"payload".to_vec(), None, None)
        .unwrap();
    let name = std::ffi::OsStr::from_bytes(b"legacy-\xff");
    if fs::write(root.join(name), b"").is_err() {
        eprintln!("filesystem refuses non-UTF-8 names");
        return;
    }
    fs::remove_file(root.join(name)).unwrap();
    let out = root.join("out");

    read(builder.to_bytes().unwrap())
        .extract_to_dir(&out, &ExtractDirOptions::default())
        .unwrap();

    assert_eq!(fs::read(out.join(name)).unwrap(), b"payload");
}

#[cfg(unix)]
#[test]
fn legacy_symlinks_follow_the_same_rules() {
    let root = scratch::case("extract-to-dir-legacy-links");
    let mut builder = Builder::new(ArchiveVersion::Rar29);
    builder
        .add_bytes(b"c/target.txt".to_vec(), b"target".to_vec(), None, None)
        .unwrap();
    for (name, target) in [
        (b"a/sym.txt".as_slice(), b"../c/target.txt".as_slice()),
        (b"a/out.txt", b"../../outside.txt"),
        (b"a/abs.txt", b"/etc/passwd"),
    ] {
        builder
            .add_unix_symlink(name.to_vec(), target.to_vec(), false, None, None)
            .unwrap();
    }

    let extracted = read(builder.to_bytes().unwrap())
        .extract_to_dir(&root, &ExtractDirOptions::default())
        .unwrap();

    assert_eq!(fs::read(root.join("a/sym.txt")).unwrap(), b"target");
    let skipped: Vec<_> = extracted
        .skipped_links
        .iter()
        .map(|link| (link.name.as_slice(), link.target.as_slice()))
        .collect();
    assert_eq!(
        skipped,
        [
            (b"a/out.txt".as_slice(), b"../../outside.txt".as_slice()),
            (b"a/abs.txt", b"/etc/passwd"),
        ]
    );
    assert!(fs::symlink_metadata(root.join("a/out.txt")).is_err());
    assert!(fs::symlink_metadata(root.join("a/abs.txt")).is_err());
}

#[test]
fn overwrite_policies() {
    let root = scratch::case("extract-to-dir-overwrite");
    let mut builder = Builder::new(ArchiveVersion::Rar50);
    builder
        .add_bytes(b"file.txt".to_vec(), b"new".to_vec(), None, None)
        .unwrap();
    let archive = read(builder.to_bytes().unwrap());
    fs::write(root.join("file.txt"), b"old").unwrap();

    let error = archive
        .extract_to_dir(&root, &ExtractDirOptions::default())
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Io);
    assert!(error.to_string().contains("already exists"), "{error}");
    assert_eq!(fs::read(root.join("file.txt")).unwrap(), b"old");

    let renamed = archive
        .extract_to_dir(
            &root,
            &ExtractDirOptions::new().with_overwrite(OverwritePolicy::Rename),
        )
        .unwrap();
    assert_eq!(renamed.paths, [root.join("file(1).txt")]);
    assert_eq!(fs::read(root.join("file.txt")).unwrap(), b"old");
    assert_eq!(fs::read(root.join("file(1).txt")).unwrap(), b"new");

    archive
        .extract_to_dir(
            &root,
            &ExtractDirOptions::new().with_overwrite(OverwritePolicy::Always),
        )
        .unwrap();
    assert_eq!(fs::read(root.join("file.txt")).unwrap(), b"new");
    assert_eq!(tree(&root), paths(&["file.txt", "file(1).txt"]));
}

/// A stored archive whose second member's data fails its checksum.
fn with_a_corrupt_member() -> Vec<u8> {
    let mut builder = Builder::new(ArchiveVersion::Rar50).store(true);
    for (name, data) in [
        (b"first.txt".as_slice(), b"first payload".as_slice()),
        (b"broken.txt", b"broken payload"),
        (b"last.txt", b"last payload"),
    ] {
        builder
            .add_bytes(name.to_vec(), data.to_vec(), None, None)
            .unwrap();
    }
    let mut bytes = builder.to_bytes().unwrap();
    let at = bytes
        .windows(14)
        .position(|window| window == b"broken payload")
        .unwrap();
    bytes[at] ^= 0xff;
    bytes
}

#[test]
fn a_member_the_handler_goes_past_leaves_no_file() {
    let root = scratch::case("extract-to-dir-member-errors");
    let seen = Mutex::new(Vec::new());
    let handler = recorded(&seen);
    let options = ExtractDirOptions::new()
        .with_read_options(ArchiveReadOptions::new().with_member_error_handler(&handler));

    let extracted = read(with_a_corrupt_member())
        .extract_to_dir(&root, &options)
        .unwrap();

    assert_eq!(seen.lock().unwrap().len(), 1);
    assert_eq!(seen.lock().unwrap()[0].0, b"broken.txt");
    assert_eq!(
        extracted.paths,
        [root.join("first.txt"), root.join("last.txt")]
    );
    assert_eq!(tree(&root), paths(&["first.txt", "last.txt"]));
}

#[test]
fn a_member_that_fails_verification_leaves_nothing_at_any_thread_count() {
    let root = scratch::case("extract-to-dir-unverified");
    for threads in [1, 2, 8] {
        let out = root.join(threads.to_string());
        let options = ExtractDirOptions::new()
            .with_read_options(ArchiveReadOptions::new().with_threads(threads));

        let error = read(with_a_corrupt_member())
            .extract_to_dir(&out, &options)
            .unwrap_err();

        assert_eq!(
            error.kind(),
            ErrorKind::ChecksumMismatch,
            "threads={threads}"
        );
        assert_eq!(tree(&out), paths(&["first.txt"]), "threads={threads}");

        let seen = Mutex::new(Vec::new());
        let handler = recorded(&seen);
        let out = root.join(format!("{threads}-handled"));
        let options = ExtractDirOptions::new().with_read_options(
            ArchiveReadOptions::new()
                .with_threads(threads)
                .with_member_error_handler(&handler),
        );

        read(with_a_corrupt_member())
            .extract_to_dir(&out, &options)
            .unwrap();

        assert_eq!(
            tree(&out),
            paths(&["first.txt", "last.txt"]),
            "threads={threads}"
        );
    }
}

#[test]
fn salvage_keeps_what_a_failed_member_delivered() {
    let root = scratch::case("extract-to-dir-salvage");
    let seen = Mutex::new(Vec::new());
    let handler = recorded(&seen);
    let read_options = ArchiveReadOptions::new()
        .with_salvage(true)
        .with_member_error_handler(&handler);
    let archive =
        ArchiveReader::read_owned_with_options(with_a_corrupt_member(), read_options).unwrap();

    archive
        .extract_to_dir(
            &root,
            &ExtractDirOptions::new().with_read_options(read_options),
        )
        .unwrap();

    assert_eq!(seen.lock().unwrap().len(), 1);
    assert_eq!(tree(&root), paths(&["broken.txt", "first.txt", "last.txt"]));
    let broken = fs::read(root.join("broken.txt")).unwrap();
    assert_eq!(broken.len(), b"broken payload".len());
    assert_eq!(&broken[1..], b"roken payload");
}

#[test]
fn volume_sets_extract_with_names_and_times() {
    let root = scratch::case("extract-to-dir-volumes");
    for format in [ArchiveVersion::Rar29, ArchiveVersion::Rar50] {
        // RAR 5 names are Unicode, so the encoding leaves them alone.
        let (stored, name) = match format {
            ArchiveVersion::Rar50 => ("café.txt".as_bytes(), "café.txt"),
            _ => (b"caf\x82.txt".as_slice(), "café.txt"),
        };
        let payload = b"volume".repeat(2000);
        let mut builder = Builder::new(format).store(true).volume_size(Some(4096));
        builder
            .add_bytes(stored.to_vec(), payload.clone(), time(FILE_TIME), None)
            .unwrap();
        let volumes: Vec<_> = builder
            .build_volumes(None)
            .unwrap()
            .into_iter()
            .map(read)
            .collect();
        assert!(volumes.len() > 1);
        let mut read_options = ArchiveReadOptions::new();
        read_options.legacy_name_encoding = Some(rars::filename::LegacyNameEncoding::Cp850);
        let out = root.join(format.to_string());

        let extracted = rars::extract_volumes_to_dir(
            &volumes,
            &out,
            &ExtractDirOptions::new().with_read_options(read_options),
        )
        .unwrap();

        assert_eq!(extracted.paths, [out.join(name)]);
        assert_eq!(fs::read(out.join(name)).unwrap(), payload);
        assert_eq!(modified(&out.join(name)), stored_time(&volumes[0], stored));
    }
}

#[test]
fn an_empty_volume_set_is_refused() {
    let root = scratch::case("extract-to-dir-no-volumes");
    let error =
        rars::extract_volumes_to_dir(&[], &*root, &ExtractDirOptions::default()).unwrap_err();
    assert!(matches!(error, rars::Error::InvalidHeader(_)), "{error}");
}

#[cfg(unix)]
fn mode_of(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    fs::symlink_metadata(path).unwrap().permissions().mode() & 0o7777
}

fn unix_modes_rar5() -> Vec<u8> {
    let mut builder = Builder::new(ArchiveVersion::Rar50).store(true);
    for (name, mode) in [
        ("600", 0o600),
        ("755", 0o755),
        ("750", 0o750),
        ("777", 0o777),
        ("400", 0o400),
    ] {
        builder
            .add_bytes(
                name.as_bytes().to_vec(),
                name.as_bytes().to_vec(),
                None,
                Some(0o100000 | mode),
            )
            .unwrap();
    }
    builder
        .add_directory(b"private".to_vec(), None, Some(0o700))
        .unwrap();
    builder
        .add_bytes(
            b"private/604".to_vec(),
            b"604".to_vec(),
            None,
            Some(0o100604),
        )
        .unwrap();
    builder.to_bytes().unwrap()
}

#[cfg(unix)]
#[test]
fn unix_modes_are_restored_exactly_at_any_thread_count() {
    let root = scratch::case("extract-to-dir-unix-modes");
    let archive = read(unix_modes_rar5());
    for threads in [1, 2, 8] {
        let out = root.join(threads.to_string());
        let options = ExtractDirOptions::new()
            .with_read_options(ArchiveReadOptions::new().with_threads(threads));

        archive.extract_to_dir(&out, &options).unwrap();

        for (name, mode) in [
            ("600", 0o600),
            ("755", 0o755),
            ("750", 0o750),
            ("777", 0o777),
            ("400", 0o400),
            ("private", 0o700),
            ("private/604", 0o604),
        ] {
            assert_eq!(mode_of(&out.join(name)), mode, "threads={threads} {name}");
        }
    }
}

#[cfg(unix)]
fn default_modes(root: &Path) -> (u32, u32) {
    let file = root.join("default-file");
    let dir = root.join("default-dir");
    fs::write(&file, b"").unwrap();
    fs::create_dir(&dir).unwrap();
    (mode_of(&file), mode_of(&dir))
}

#[cfg(unix)]
#[test]
fn dos_read_only_files_become_0444_and_others_keep_the_defaults() {
    let root = scratch::case("extract-to-dir-dos-modes");
    let (file_default, dir_default) = default_modes(&root);
    let mut builder = Builder::new(ArchiveVersion::Rar50).store(true);
    builder.add_directory(b"dir".to_vec(), None, None).unwrap();
    builder.set_dos_attributes(b"dir", 0x10 | 0x01).unwrap();
    for name in ["dir/readonly", "dir/plain"] {
        builder
            .add_bytes(name.as_bytes().to_vec(), b"x".to_vec(), None, None)
            .unwrap();
    }
    builder
        .set_dos_attributes(b"dir/readonly", 0x20 | 0x01)
        .unwrap();
    let out = root.join("out");

    read(builder.to_bytes().unwrap())
        .extract_to_dir(&out, &ExtractDirOptions::new())
        .unwrap();

    assert_eq!(mode_of(&out.join("dir/readonly")), 0o444);
    assert_eq!(mode_of(&out.join("dir/plain")), file_default);
    assert_eq!(mode_of(&out.join("dir")), dir_default);
}

#[cfg(unix)]
#[test]
fn a_unix_value_without_file_type_bits_is_not_applied() {
    use rars::rar15_40::{write_stored_archive, StoredEntry, WriterOptions};
    let root = scratch::case("extract-to-dir-untyped-mode");
    let (file_default, _) = default_modes(&root);
    let archive = write_stored_archive(
        &[StoredEntry {
            name: b"untyped",
            data: b"x",
            file_time: 0,
            file_attr: 0o600,
            host_os: 3,
            password: None,
            file_comment: None,
        }],
        WriterOptions::new(ArchiveVersion::Rar40, rars::FeatureSet::store_only()),
    )
    .unwrap();
    let out = root.join("out");

    read(archive)
        .extract_to_dir(&out, &ExtractDirOptions::new())
        .unwrap();

    assert_eq!(mode_of(&out.join("untyped")), file_default);
}

#[cfg(unix)]
#[test]
fn modes_are_left_alone_when_asked() {
    let root = scratch::case("extract-to-dir-no-modes");
    let (file_default, dir_default) = default_modes(&root);
    let out = root.join("out");
    let options = ExtractDirOptions::new().with_restore_modes(false);

    read(unix_modes_rar5())
        .extract_to_dir(&out, &options)
        .unwrap();

    for name in ["600", "755", "750", "777", "400", "private/604"] {
        assert_eq!(mode_of(&out.join(name)), file_default, "{name}");
    }
    assert_eq!(mode_of(&out.join("private")), dir_default);
}

fn copies_of_a_file_at_rar5(mode: u32) -> Vec<u8> {
    let payload = b"locked".to_vec();
    let mut builder = Builder::new(ArchiveVersion::Rar50).store(true);
    builder
        .add_bytes(
            b"locked".to_vec(),
            payload.clone(),
            None,
            Some(0o100000 | mode),
        )
        .unwrap();
    for name in ["hard", "copy"] {
        builder
            .add_unix_symlink(
                name.as_bytes().to_vec(),
                b"locked".to_vec(),
                false,
                None,
                None,
            )
            .unwrap();
    }
    let Archive::Rar50Plus(mut rar5) = read(builder.to_bytes().unwrap()) else {
        unreachable!()
    };
    for block in &mut rar5.blocks {
        if let rars::rar50::Block::File(file) = block {
            if let Some(redirection) = file.redirection.as_mut() {
                // Hard link 4, file copy 5.
                redirection.redirection_type = if file.name == b"hard" { 4 } else { 5 };
                file.attributes = u64::from(0o100000 | mode);
                file.unpacked_size = payload.len() as u64;
            }
        }
    }
    let mutated = Archive::Rar50Plus(rar5);
    let mut builder = Builder::new(ArchiveVersion::Rar50).store(true);
    for member in mutated.members() {
        if member.meta.name == b"locked" {
            builder
                .add_bytes(
                    b"locked".to_vec(),
                    payload.clone(),
                    None,
                    Some(0o100000 | mode),
                )
                .unwrap();
        } else {
            builder.add_archive_redirection(&member).unwrap();
        }
    }
    builder.to_bytes().unwrap()
}

#[cfg(unix)]
#[test]
fn files_later_members_copy_keep_their_modes_even_unreadable_ones() {
    use std::os::unix::fs::PermissionsExt;
    let root = scratch::case("extract-to-dir-copied-source");
    for mode in [0o400, 0o200] {
        let out = root.join(format!("{mode:o}"));

        read(copies_of_a_file_at_rar5(mode))
            .extract_to_dir(&out, &ExtractDirOptions::new())
            .unwrap();

        for name in ["locked", "hard", "copy"] {
            assert_eq!(mode_of(&out.join(name)), mode, "{mode:o} {name}");
        }
        fs::set_permissions(out.join("copy"), fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(fs::read(out.join("copy")).unwrap(), b"locked", "{mode:o}");
    }
}

const SYMLINK: u64 = 1;
const HARD_LINK: u64 = 4;
const FILE_COPY: u64 = 5;

fn rar5_links(links: &[(&str, u64, &str)]) -> Vec<u8> {
    // The RAR 5 writer, unlike Builder, takes a link whose target is a symlink.
    use rars::rar50::{self, ArchiveEntry, ArchiveExtras, Block, WriterOptions};
    use rars::EntrySource;
    let payload = b"payload".to_vec();
    // A redirection can't be built outside the crate, so one is read back.
    let mut builder = Builder::new(ArchiveVersion::Rar50);
    builder
        .add_unix_symlink(b"x".to_vec(), b"x".to_vec(), false, None, None)
        .unwrap();
    let Archive::Rar50Plus(rar5) = read(builder.to_bytes().unwrap()) else {
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
    let mut entries = vec![
        unix(
            ArchiveEntry::new("d", EntrySource::from_bytes(Vec::new())).with_directory(true),
            0o040755,
        ),
        unix(
            ArchiveEntry::new("f", EntrySource::from_bytes(payload.clone())),
            0o100644,
        ),
    ];
    for &(name, kind, target) in links {
        let mut redirection = symlink.clone();
        redirection.redirection_type = kind;
        redirection.flags = u64::from(target == "d");
        redirection.target_name = target.as_bytes().to_vec();
        let entry = ArchiveEntry::new(name, EntrySource::from_bytes(Vec::new()))
            .with_redirection(Some(redirection));
        entries.push(if kind == SYMLINK {
            unix(entry, 0o120777)
        } else {
            // A link has its target's size, and a symlink has none.
            let size = if target == "f" {
                payload.len() as u64
            } else {
                0
            };
            unix(entry.with_redirection_size(Some(size)), 0o100644)
        });
    }
    let mut out = Vec::new();
    rar50::write_streaming_archive_to(
        &entries,
        WriterOptions::default(),
        ArchiveExtras::default(),
        &rars::WriterResources::default(),
        &mut out,
    )
    .unwrap();
    out
}

#[cfg(unix)]
#[test]
fn skip_symlinks_leaves_out_symlinks_and_keeps_hard_links() {
    let root = scratch::case("extract-to-dir-skip-symlinks");
    let bytes = rar5_links(&[
        ("sl", SYMLINK, "f"),
        ("dl", SYMLINK, "d"),
        ("hl", HARD_LINK, "f"),
    ]);
    for skip in [false, true] {
        let out = root.join(skip.to_string());

        let extracted = read(bytes.clone())
            .extract_to_dir(&out, &ExtractDirOptions::new().with_skip_symlinks(skip))
            .unwrap();

        let mut expected = vec!["d", "f", "hl"];
        if !skip {
            expected.extend(["sl", "dl"]);
        }
        assert_eq!(tree(&out), paths(&expected), "skip={skip}");
        assert_eq!(fs::read(out.join("hl")).unwrap(), b"payload");
        assert!(extracted.skipped_links.is_empty(), "skip={skip}");
    }
}

#[cfg(unix)]
#[test]
fn skip_symlinks_leaves_out_legacy_symlinks() {
    let root = scratch::case("extract-to-dir-skip-legacy-symlinks");
    let mut builder = Builder::new(ArchiveVersion::Rar29);
    builder
        .add_bytes(b"f".to_vec(), b"payload".to_vec(), None, None)
        .unwrap();
    builder
        .add_unix_symlink(b"sl".to_vec(), b"f".to_vec(), false, None, None)
        .unwrap();
    builder
        .add_bytes(b"after".to_vec(), b"after".to_vec(), None, None)
        .unwrap();
    let bytes = builder.to_bytes().unwrap();
    for skip in [false, true] {
        let out = root.join(skip.to_string());

        let extracted = read(bytes.clone())
            .extract_to_dir(&out, &ExtractDirOptions::new().with_skip_symlinks(skip))
            .unwrap();

        let mut expected = vec!["f", "after"];
        if !skip {
            expected.push("sl");
        }
        assert_eq!(tree(&out), paths(&expected), "skip={skip}");
        assert_eq!(fs::read(out.join("after")).unwrap(), b"after");
        assert!(extracted.skipped_links.is_empty(), "skip={skip}");
    }
}

#[cfg(unix)]
#[test]
fn links_to_a_skipped_symlink_fail_as_their_own_members() {
    let root = scratch::case("extract-to-dir-links-to-skipped");
    let bytes = rar5_links(&[
        ("sl", SYMLINK, "f"),
        ("hl", HARD_LINK, "sl"),
        ("cp", FILE_COPY, "sl"),
    ]);
    let seen = Mutex::new(Vec::new());
    let handler = recorded(&seen);
    let options = ExtractDirOptions::new()
        .with_skip_symlinks(true)
        .with_read_options(ArchiveReadOptions::new().with_member_error_handler(&handler));
    let out = root.join("handled");

    read(bytes.clone()).extract_to_dir(&out, &options).unwrap();

    assert_eq!(
        *seen.lock().unwrap(),
        [
            (b"hl".to_vec(), ErrorKind::InvalidArgument),
            (b"cp".to_vec(), ErrorKind::InvalidArgument),
        ]
    );
    assert_eq!(tree(&out), paths(&["d", "f"]));
    assert_eq!(fs::read(out.join("f")).unwrap(), b"payload");

    let error = read(bytes)
        .extract_to_dir(
            root.join("unhandled"),
            &ExtractDirOptions::new().with_skip_symlinks(true),
        )
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidArgument);
    assert!(
        error.to_string().contains("symbolic link left out"),
        "{error}"
    );
}

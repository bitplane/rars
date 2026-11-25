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

fn read_vint(data: &[u8], mut at: usize) -> (u64, usize) {
    let mut value = 0;
    let mut shift = 0;
    loop {
        let byte = data[at];
        at += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return (value, at);
        }
        shift += 7;
    }
}

/// Swaps a RAR 5 member name for one of the same length and repairs the
/// header CRC, giving a well-formed archive the builder would refuse to make.
fn rewrite_rar5_name(archive: &[u8], placeholder: &[u8], replacement: &[u8]) -> Vec<u8> {
    assert_eq!(placeholder.len(), replacement.len());
    let mut patched = archive.to_vec();
    let mut at = 8;
    while at + 4 < archive.len() {
        let body_at = at + 4;
        let (size, after_size) = read_vint(archive, body_at);
        let body_end = after_size + size as usize;
        let (kind, cursor) = read_vint(archive, after_size);
        let (flags, mut cursor) = read_vint(archive, cursor);
        if flags & 1 != 0 {
            cursor = read_vint(archive, cursor).1;
        }
        let data_size = if flags & 2 != 0 {
            read_vint(archive, cursor).0 as usize
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

    // Stored attributes are not applied: the read-only file stays writable.
    assert!(!fs::metadata(out.join("windows/readonly.txt"))
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

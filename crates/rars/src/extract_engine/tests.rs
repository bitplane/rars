use super::staged::{checked_output_path, open_output_writer, StagedFile};
use super::*;
use crate::{ArchiveFamily, Error, ExtractedEntryMeta};
use std::collections::HashMap;

const FSREDIR_UNIX_SYMLINK: u64 = 0x01;
const FSREDIR_HARDLINK: u64 = 0x04;
const FSREDIR_FILE_COPY: u64 = 0x05;
const HOST5_UNIX: u64 = 1;

fn scratch(name: &str) -> crate::scratch::Scratch {
    crate::scratch::case(&format!("rars-engine-{name}"))
}

fn output_relative_path(name: &[u8]) -> crate::Result<PathBuf> {
    crate::filename::relative_path(name, true)
}

fn rar50_entry_name(name: &[u8], host_os: u64) -> Vec<u8> {
    crate::output_links::rar50_native_name(name, host_os == HOST5_UNIX)
}

fn rar50_output_relative_path(name: &[u8], host_os: u64) -> crate::Result<PathBuf> {
    rar50_relative_path(name, host_os == HOST5_UNIX)
}

#[cfg(unix)]
fn supports_raw_byte_names(root: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let name = b"raw-name-probe-\xff";
    let path = root.join(std::ffi::OsStr::from_bytes(name));
    if fs::write(&path, []).is_err() {
        return false;
    }
    let exact = fs::read_dir(root)
        .unwrap()
        .any(|entry| entry.unwrap().file_name().as_bytes() == name);
    fs::remove_file(path).unwrap();
    exact
}

#[test]
fn a_path_reserved_twice_is_refused() {
    let root = scratch("reserve-twice");
    let file = root.join("plain.txt");
    let mut state = ExtractEngine::new(
        &root,
        OverwritePolicy::Always,
        false,
        false,
        ArchiveFamily::Rar50Plus,
    );
    state.reserve_output_path(file.clone()).unwrap();
    assert!(matches!(
        state.reserve_output_path(file),
        Err(Error::InvalidHeader(
            "multiple archive entries map to the same output path"
        ))
    ));
}

fn write_verified(state: &mut ExtractEngine<'_>, meta: &ExtractedEntryMeta, data: &[u8]) {
    let mut writer = state.open_settled(meta).unwrap();
    std::io::Write::write_all(&mut writer, data).unwrap();
    drop(writer);
    assert!(!state.settle(true).unwrap());
}

/// Staged files are created with their member's permission bits. Each
/// ends with exactly those bits, whether the umask kept them, so that
/// nothing changes them after, or cleared some, so that they are set.
#[cfg(any(target_vendor = "apple", target_os = "linux", target_os = "android"))]
#[test]
fn staged_files_end_with_their_members_mode_whatever_the_umask_clears() {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    let root = scratch("created-modes");
    let mut tree = crate::output_tree::OutputTree::open(&root)
        .unwrap()
        .unwrap();
    let dir = tree.file_dir(std::path::Path::new("files")).unwrap();
    let created_modes = crate::output_modes::CreatedModes::default();
    let modes = [
        0o600, 0o644, 0o777, 0o755, 0o664, 0o600, 0o777, 0o644, 0o400,
    ];
    for (index, mode) in modes.into_iter().enumerate() {
        let name = std::ffi::OsString::from(index.to_string());
        let meta = ExtractedEntryMeta::new(b"member".to_vec(), None, 0o100000 | mode as u64, false)
            .with_attr_source(crate::AttrSource::Unix);
        let (mut file, closed) =
            StagedFile::deferred(dir.clone(), name, &meta, true, true, created_modes.clone());
        if index % 2 == 1 {
            file.create().unwrap();
        }
        file.write_all(b"data").unwrap();
        drop(file);
        assert!(
            closed.early_set.load(std::sync::atomic::Ordering::Acquire),
            "{mode:o}"
        );
        let path = root.join("files").join(index.to_string());
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o7777,
            mode,
            "{index}: {mode:o}"
        );
    }
}

#[test]
fn staging_aliases_are_rejected_using_existing_filesystem_ancestors() {
    let root = scratch("staging-alias");
    let mut state = ExtractEngine::new(
        &root,
        OverwritePolicy::Always,
        false,
        false,
        ArchiveFamily::Rar50Plus,
    );
    write_verified(
        &mut state,
        &crate::ExtractedEntryMeta::new(b"ordinary".to_vec(), None, 0, false),
        b"",
    );
    let storage = state.publisher.state().staging().unwrap().root.clone();
    let alias = storage
        .file_name()
        .unwrap()
        .to_string_lossy()
        .to_uppercase();
    // On a case-sensitive host this distinct name is a legitimate output.
    let aliases_storage = root.join(&alias).exists();
    let name = format!("{alias}/payload").into_bytes();
    let result = state.open_settled(&crate::ExtractedEntryMeta::new(name, None, 0, false));
    if aliases_storage {
        assert!(matches!(
            &result,
            Err(Error::InvalidHeader(
                "archive path conflicts with extraction storage"
            ))
        ));
        // The earlier member is published as the run ends at the refusal,
        // leaving nothing staged, only perhaps the empty directory files
        // stage in.
        assert!(state.settle(false).unwrap(), "its open failed");
        state.publish_verified_and_wait().unwrap();
        let staged: Vec<_> = fs::read_dir(&storage)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| !path.is_dir() || fs::read_dir(path).unwrap().next().is_some())
            .collect();
        assert!(staged.is_empty(), "{staged:?}");
        assert!(root.join("ordinary").exists());
    } else {
        assert!(result.is_ok());
    }
}

#[test]
fn path_validation_rejects_empty_drive_root_and_parent_names() {
    let dir = scratch("path-validation");
    for name in [
        b"".as_slice(),
        b".",
        b"./",
        b"C:relative",
        b"z:/absolute",
        b"/absolute",
        b"../escape",
        b"name\0suffix",
    ] {
        assert!(output_relative_path(name).is_err(), "{name:?}");
        let meta = ExtractedEntryMeta::new(name.to_vec(), None, 0, false);
        assert!(crate::filename::relative_path(&meta.name, true).is_err());
        let (mut rar50_meta, _) = redirection_fixture();
        rar50_meta.name = name.to_vec();
        assert!(output_path_for_rar50_entry(&dir, &rar50_meta).is_err());
    }
    for path in [
        Path::new("../escape"),
        Path::new("/absolute"),
        Path::new("."),
    ] {
        assert!(checked_output_path(&dir, path).is_err());
    }
    assert_eq!(
        output_relative_path(b"./nested/./file").unwrap(),
        Path::new("nested/file")
    );
}

#[cfg(unix)]
#[test]
fn writers_refuse_symlink_parents_and_redirections_report_permission_errors() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let dir = scratch("output-filesystem-errors");
    let target = dir.join("target");
    fs::create_dir(&target).unwrap();
    symlink(&target, dir.join("link")).unwrap();
    let meta = ExtractedEntryMeta::new(b"link/child".to_vec(), None, 0, false);
    assert!(open_test_writer(&dir, &meta, OverwritePolicy::Always).is_err());
    assert_eq!(fs::read_dir(&target).unwrap().count(), 0);
    let (mut link_meta, mut link_redirection) = redirection_fixture();
    link_meta.name = b"link/child".to_vec();
    link_redirection.redirection_type = FSREDIR_UNIX_SYMLINK;
    link_redirection.target_name = b"target".to_vec();
    assert!(create_rar50_redirection(
        &dir,
        &link_meta,
        &link_redirection,
        OverwritePolicy::Always,
        &HashMap::new()
    )
    .is_err());
    assert_eq!(fs::read_dir(&target).unwrap().count(), 0);
    let locked = dir.join("locked");
    fs::create_dir(&locked).unwrap();
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o500)).unwrap();
    let permission_bits_enforced = fs::write(locked.join("probe"), b"probe").is_err();
    let (mut meta, mut redirection) = redirection_fixture();
    meta.name = b"locked/child".to_vec();
    redirection.redirection_type = FSREDIR_UNIX_SYMLINK;
    redirection.target_name = b"target".to_vec();
    let result = create_rar50_redirection(
        &dir,
        &meta,
        &redirection,
        OverwritePolicy::Always,
        &HashMap::new(),
    );
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o700)).unwrap();
    if !permission_bits_enforced {
        eprintln!("permission-denial case unavailable on privileged runner");
        return;
    }
    assert!(result.is_err());
    assert!(!locked.join("child").exists());
}

#[test]
fn output_creation_preserves_existing_files_on_refusal() {
    let dir = scratch("writer-errors");
    let mut meta = ExtractedEntryMeta::new(b"existing".to_vec(), None, 0, false);
    fs::write(dir.join("existing"), b"keep").unwrap();
    assert!(open_test_writer(&dir, &meta, OverwritePolicy::Never).is_err());
    assert_eq!(fs::read(dir.join("existing")).unwrap(), b"keep");
    for name in [b"../escape".as_slice(), b"invalid\0name"] {
        meta.name = name.to_vec();
        assert!(open_test_writer(&dir, &meta, OverwritePolicy::Always).is_err());
    }
    meta.name = b"existing/child".to_vec();
    for directory in [false, true] {
        meta.is_directory = directory;
        assert!(open_test_writer(&dir, &meta, OverwritePolicy::Always).is_err());
    }
    assert_eq!(fs::read(dir.join("existing")).unwrap(), b"keep");
}

#[test]
fn redirections_replace_empty_directories_but_preserve_nonempty_ones() {
    let dir = scratch("redirection-directories");
    let (mut meta, mut redirection) = redirection_fixture();
    meta.name = b"destination".to_vec();
    redirection.redirection_type = FSREDIR_FILE_COPY;
    redirection.target_name = b"source".to_vec();
    let source = dir.join("source");
    fs::write(&source, b"payload").unwrap();
    let created = HashMap::from([(PathBuf::from("source"), source)]);
    let destination = dir.join("destination");
    fs::create_dir(&destination).unwrap();
    assert!(
        create_rar50_redirection(&dir, &meta, &redirection, OverwritePolicy::Never, &created)
            .is_err()
    );
    assert!(destination.is_dir());
    fs::write(destination.join("keep"), b"keep").unwrap();
    assert!(
        create_rar50_redirection(&dir, &meta, &redirection, OverwritePolicy::Always, &created)
            .is_err()
    );
    assert_eq!(fs::read(destination.join("keep")).unwrap(), b"keep");
    fs::remove_file(destination.join("keep")).unwrap();
    create_rar50_redirection(&dir, &meta, &redirection, OverwritePolicy::Always, &created).unwrap();
    assert_eq!(fs::read(&destination).unwrap(), b"payload");
    // Windows can report NotFound for a child below a regular file. The
    // redirection operation still has to reject that parent before writing.
    meta.name = b"destination/child".to_vec();
    assert!(matches!(
        create_rar50_redirection(&dir, &meta, &redirection, OverwritePolicy::Always, &created),
        Err(Error::Io(_))
    ));
    assert!(!destination.join("child").exists());
    assert_eq!(fs::read(&destination).unwrap(), b"payload");
}

#[test]
fn verified_redirection_publication_replaces_only_empty_directories() {
    let mut kinds = vec![FSREDIR_FILE_COPY, FSREDIR_HARDLINK];
    if cfg!(unix) {
        kinds.push(FSREDIR_UNIX_SYMLINK);
    }
    for kind in kinds {
        for nonempty in [false, true] {
            for overwrite in [OverwritePolicy::Never, OverwritePolicy::Always] {
                let root = scratch("verified-redirection-directory");
                let destination = root.join("destination");
                fs::create_dir(&destination).unwrap();
                if nonempty {
                    fs::write(destination.join("keep"), b"keep").unwrap();
                }
                let mut state =
                    ExtractEngine::new(&root, overwrite, false, false, ArchiveFamily::Rar50Plus);
                let (mut meta, mut redirection) = redirection_fixture();
                meta.name = b"source".to_vec();
                write_verified(&mut state, &crate::rar50_meta(&meta), b"payload");
                meta.name = b"destination".to_vec();
                redirection.target_name = b"source".to_vec();
                redirection.redirection_type = kind;
                let staged =
                    state.create_link(&crate::rar50_meta(&meta), test_link(&redirection).unwrap());
                assert!(
                    destination.is_dir(),
                    "destination changed before verification"
                );
                if overwrite == OverwritePolicy::Never {
                    assert!(staged.is_err());
                    // The earlier member was verified, so it is kept.
                    assert_eq!(fs::read(root.join("source")).unwrap(), b"payload");
                    continue;
                }
                staged.unwrap();
                let published = state.publish();
                if nonempty {
                    assert!(published.is_err());
                    assert_eq!(fs::read(destination.join("keep")).unwrap(), b"keep");
                } else {
                    published.unwrap();
                    assert_eq!(fs::read(&destination).unwrap(), b"payload");
                }
            }
        }
    }
}

#[test]
fn redirection_filesystem_and_path_errors_are_reported() {
    let dir = scratch("redirection-errors");
    let (mut meta, mut redirection) = redirection_fixture();
    meta.name = b"destination".to_vec();
    let destination = dir.join("destination");
    fs::write(&destination, b"keep").unwrap();
    for kind in [FSREDIR_HARDLINK, FSREDIR_FILE_COPY] {
        redirection.redirection_type = kind;
        redirection.target_name = b"../escape".to_vec();
        assert!(create_rar50_redirection(
            &dir,
            &meta,
            &redirection,
            OverwritePolicy::Always,
            &HashMap::new()
        )
        .is_err());
        assert_eq!(fs::read(&destination).unwrap(), b"keep");
    }
    redirection.redirection_type = FSREDIR_FILE_COPY;
    redirection.target_name = b"source".to_vec();
    let source = dir.join("source");
    fs::write(&source, b"payload").unwrap();
    let created = HashMap::from([(PathBuf::from("source"), source.clone())]);
    for name in [b"../escape".as_slice(), b"destination/child"] {
        meta.name = name.to_vec();
        for kind in [FSREDIR_FILE_COPY, FSREDIR_HARDLINK, FSREDIR_UNIX_SYMLINK] {
            redirection.redirection_type = kind;
            assert!(create_rar50_redirection(
                &dir,
                &meta,
                &redirection,
                OverwritePolicy::Always,
                &created
            )
            .is_err());
            assert_eq!(fs::read(&destination).unwrap(), b"keep");
        }
    }
    // Previously extracted sources can disappear before a later redirection.
    fs::remove_file(&source).unwrap();
    meta.name = b"new-destination".to_vec();
    for kind in [FSREDIR_HARDLINK, FSREDIR_FILE_COPY] {
        redirection.redirection_type = kind;
        assert!(create_rar50_redirection(
            &dir,
            &meta,
            &redirection,
            OverwritePolicy::Always,
            &created
        )
        .is_err());
        assert!(!dir.join("new-destination").exists());
    }
}

#[test]
fn metadata_restoration_errors_and_opt_out_are_observable() {
    let dir = scratch("metadata-errors");
    for directory in [false, true] {
        for timestamp in [
            None,
            Some(crate::Timestamp::from_unix_seconds(1_704_067_200)),
        ] {
            let output = ExtractedOutput {
                name: b"missing".to_vec(),
                stored: PathBuf::new(),
                path: dir.join("missing"),
                meta: ExtractedEntryMeta::new(
                    b"missing".to_vec(),
                    timestamp,
                    if directory { 0o040700 } else { 0o100600 },
                    directory,
                )
                .with_attr_source(crate::AttrSource::Unix),
                restore_metadata: false,
                restore_mode: true,
                restore_time: true,
            };
            restore_output_metadata(std::slice::from_ref(&output)).unwrap();
            #[cfg(unix)]
            {
                let output = ExtractedOutput {
                    restore_metadata: true,
                    ..output
                };
                assert!(restore_output_metadata(&[output]).is_err());
            }
        }
    }
}

// Keep raw RAR5 fixtures to exercise the same filename and filesystem cases.
fn test_link(link: &crate::rar50::FileRedirection) -> crate::Result<crate::ExtractedLink<'_>> {
    use crate::ExtractedLink::*;
    let target = &link.target_name;
    Ok(match link.redirection_type {
        1 | 2 => Symlink {
            target,
            directory: link.flags & 1 != 0,
        },
        3 => Junction { target },
        4 => HardLink { target },
        5 => FileCopy { target },
        _ => return Err(crate::Error::InvalidHeader("unsupported archive link type")),
    })
}
fn create_rar50_redirection(
    out: &std::path::Path,
    meta: &crate::rar50::ExtractedEntryMeta,
    link: &crate::rar50::FileRedirection,
    overwrite: OverwritePolicy,
    created: &std::collections::HashMap<std::path::PathBuf, std::path::PathBuf>,
) -> crate::Result<(std::path::PathBuf, bool)> {
    let relative = rar50_output_relative_path(&meta.name, meta.host_os)
        .map_err(|_| crate::Error::InvalidHeader("unsafe archive path"))?;
    let target = rar50_output_relative_path(&link.target_name, meta.host_os)
        .map_err(|_| crate::Error::InvalidHeader("unsafe archive redirection target"))?;
    create_link_output(
        out,
        &relative,
        &target,
        test_link(link)?,
        overwrite,
        created,
        &mut Default::default(),
        None,
    )
    .map(|(path, made)| (path, made.is_file()))
}
fn output_path_for_rar50_entry(
    out: &std::path::Path,
    meta: &crate::rar50::ExtractedEntryMeta,
) -> crate::Result<std::path::PathBuf> {
    let relative = rar50_output_relative_path(&meta.name, meta.host_os)
        .map_err(|_| crate::Error::InvalidHeader("unsafe archive path"))?;
    checked_output_path(out, &relative)
}
fn open_test_writer(
    out: &std::path::Path,
    meta: &crate::ExtractedEntryMeta,
    overwrite: OverwritePolicy,
) -> crate::Result<(std::path::PathBuf, Box<dyn std::io::Write>)> {
    let relative = crate::filename::relative_path(&meta.name, true)?;
    open_output_writer(
        out,
        &relative,
        meta.is_directory,
        overwrite,
        &mut Default::default(),
    )
    .map(|(path, writer)| (path, writer as Box<dyn std::io::Write>))
}

fn redirection_fixture() -> (
    crate::rar50::ExtractedEntryMeta,
    crate::rar50::FileRedirection,
) {
    let archive = crate::rar50::Archive::parse(include_bytes!(
        "../../tests/fixtures/rar50/wild/hardlink.rar"
    ))
    .unwrap();
    let file = archive
        .files()
        .find(|file| file.redirection.is_some())
        .unwrap();
    (file.metadata(), file.redirection.clone().unwrap())
}

#[cfg(any(target_vendor = "apple", target_os = "linux", target_os = "android"))]
#[test]
fn rar50_mapped_names_are_resolved_once_for_files_and_redirections() {
    use std::ffi::OsStr;
    use std::io::Write;
    use std::os::unix::ffi::OsStrExt;
    for kind in [FSREDIR_HARDLINK, FSREDIR_FILE_COPY, FSREDIR_UNIX_SYMLINK] {
        let dir = scratch("mapped-redirections");
        let mut state = ExtractEngine::new(
            &dir,
            OverwritePolicy::Always,
            false,
            false,
            ArchiveFamily::Rar50Plus,
        );
        let (mut meta, mut redirection) = redirection_fixture();
        meta.host_os = 1;
        // A literal marker and a private-use character must survive decoding once,
        // even if the test filesystem cannot create a literal U+FFFE filename.
        let literal = "source-\u{fffe}\u{e0ff}".as_bytes();
        meta.name = crate::filename::encode_rar50(literal).into_owned();
        assert_eq!(
            rar50_output_relative_path(&meta.name, meta.host_os)
                .unwrap()
                .as_os_str()
                .as_bytes(),
            literal
        );
        let probe = dir.join(OsStr::from_bytes(literal));
        let native = match fs::write(&probe, []) {
            Ok(()) => {
                fs::remove_file(probe).unwrap();
                literal
            }
            Err(error) if error.raw_os_error() == Some(rustix::io::Errno::ILSEQ.raw_os_error()) => {
                "source-\u{e0ff}".as_bytes()
            }
            Err(error) => panic!("literal filename probe failed unexpectedly: {error}"),
        };
        meta.name = crate::filename::encode_rar50(native).into_owned();
        state
            .open_settled(&crate::rar50_meta(&meta))
            .unwrap()
            .write_all(b"payload")
            .unwrap();
        assert_eq!(state.last_opened().unwrap().name, meta.name);
        state.settle(true).unwrap();
        redirection.target_name = meta.name.clone();
        redirection.redirection_type = kind;
        let link = if supports_raw_byte_names(&dir) {
            b"link-\xff".as_slice()
        } else {
            b"link-unicode".as_slice()
        };
        meta.name = crate::filename::encode_rar50(link).into_owned();
        state
            .create_link(&crate::rar50_meta(&meta), test_link(&redirection).unwrap())
            .unwrap();
        state.publish().unwrap();
        assert_eq!(
            fs::read(dir.join(OsStr::from_bytes(link))).unwrap(),
            b"payload"
        );
        assert_eq!(
            fs::read(dir.join(OsStr::from_bytes(native))).unwrap(),
            b"payload"
        );
    }
}

#[test]
fn rar50_redirections_keep_backslash_names_distinct_from_directories() {
    for host_os in [0, 1] {
        for kind in [FSREDIR_HARDLINK, FSREDIR_FILE_COPY, FSREDIR_UNIX_SYMLINK] {
            if kind == FSREDIR_UNIX_SYMLINK && !cfg!(unix) {
                continue;
            }
            let dir = scratch("rar50-redirection-paths");
            let mut state = ExtractEngine::new(
                &dir,
                OverwritePolicy::Always,
                false,
                false,
                ArchiveFamily::Rar50Plus,
            );
            let (mut meta, mut redirection) = redirection_fixture();
            meta.host_os = host_os;
            for (name, data) in [
                (&br"sub\file"[..], &b"literal"[..]),
                (b"sub/file", b"nested"),
                (b"links/item", b"existing destination"),
            ] {
                meta.name = name.to_vec();
                write_verified(&mut state, &crate::rar50_meta(&meta), data);
            }

            meta.name = br"links\item".to_vec();
            redirection.redirection_type = kind;
            redirection.target_name = br"sub\file".to_vec();
            state
                .create_link(&crate::rar50_meta(&meta), test_link(&redirection).unwrap())
                .unwrap();
            let (source, destination) = if cfg!(unix) && host_os == 1 {
                (r"sub\file", r"links\item")
            } else {
                ("sub_file", "links_item")
            };
            if kind != FSREDIR_UNIX_SYMLINK {
                // Redirections must also be recorded under the same path rules.
                meta.name = b"chain".to_vec();
                redirection.target_name = br"links\item".to_vec();
                state
                    .create_link(&crate::rar50_meta(&meta), test_link(&redirection).unwrap())
                    .unwrap();
            }
            state.publish().unwrap();
            assert_eq!(fs::read(dir.join(destination)).unwrap(), b"literal");
            assert_eq!(fs::read(dir.join("sub/file")).unwrap(), b"nested");
            assert_eq!(
                fs::read(dir.join("links/item")).unwrap(),
                b"existing destination"
            );
            if kind == FSREDIR_UNIX_SYMLINK {
                assert_eq!(
                    fs::read_link(dir.join(destination)).unwrap(),
                    Path::new(source)
                );
            } else {
                assert_eq!(fs::read(dir.join("chain")).unwrap(), b"literal");
            }
        }
    }
}

#[test]
fn rar50_redirections_reject_colliding_output_names() {
    for host_os in [0, 1] {
        let dir = scratch("rar50-redirection-collision");
        let mut state = ExtractEngine::new(
            &dir,
            OverwritePolicy::Always,
            false,
            false,
            ArchiveFamily::Rar50Plus,
        );
        let (mut meta, mut redirection) = redirection_fixture();
        meta.host_os = host_os;
        meta.name = br"same\name".to_vec();
        write_verified(&mut state, &crate::rar50_meta(&meta), b"keep me");
        let name = if cfg!(unix) && host_os == 1 {
            r"same\name"
        } else {
            "same_name"
        };
        meta.name = format!("./{name}").into_bytes();
        redirection.redirection_type = FSREDIR_FILE_COPY;
        redirection.target_name = br"same\name".to_vec();
        assert!(matches!(
            state.create_link(&crate::rar50_meta(&meta), test_link(&redirection).unwrap()),
            Err(Error::InvalidHeader(
                "multiple archive entries map to the same output path"
            ))
        ));
        state.publish().unwrap();
        assert_eq!(fs::read(dir.join(name)).unwrap(), b"keep me");
    }
}

#[test]
fn invalid_redirections_preserve_existing_destinations() {
    let dir = scratch("invalid-redirections");
    let (mut meta, mut redirection) = redirection_fixture();
    meta.name = b"destination".to_vec();
    let destination = dir.join("destination");
    for (kind, target) in [
        (99, &b"source"[..]),
        (FSREDIR_UNIX_SYMLINK, b"../escape"),
        (FSREDIR_HARDLINK, b"missing"),
        (FSREDIR_FILE_COPY, b"missing"),
    ] {
        fs::write(&destination, b"keep me").unwrap();
        redirection.redirection_type = kind;
        redirection.target_name = target.to_vec();
        assert!(create_rar50_redirection(
            &dir,
            &meta,
            &redirection,
            OverwritePolicy::Always,
            &HashMap::new(),
        )
        .is_err());
        assert_eq!(fs::read(&destination).unwrap(), b"keep me", "type {kind}");
    }
}

#[test]
fn valid_copy_redirection_obeys_overwrite_policy() {
    let dir = scratch("copy-redirection");
    let (mut meta, mut redirection) = redirection_fixture();
    meta.name = b"destination".to_vec();
    redirection.redirection_type = FSREDIR_FILE_COPY;
    redirection.target_name = b"source".to_vec();
    let destination = dir.join("destination");
    let source = dir.join("source");
    fs::write(&destination, b"old").unwrap();
    fs::write(&source, b"new").unwrap();
    let created = HashMap::from([(PathBuf::from("source"), source)]);
    assert!(
        create_rar50_redirection(&dir, &meta, &redirection, OverwritePolicy::Never, &created,)
            .is_err()
    );
    assert_eq!(fs::read(&destination).unwrap(), b"old");
    create_rar50_redirection(&dir, &meta, &redirection, OverwritePolicy::Always, &created).unwrap();
    assert_eq!(fs::read(&destination).unwrap(), b"new");
}

/// RAR 5.0 separates with `/` on every host, so a backslash in a name is a
/// character. Splitting on it invents a directory the archive never
/// declared. RAR 1.5-4.x is the opposite and must keep splitting.
///
/// Unix keeps a Unix-host entry verbatim. Other platforms and Windows-host
/// entries map backslashes to `_`, without adding directory levels.
#[test]
fn rar50_backslash_is_a_character_and_legacy_backslash_is_a_separator() {
    const UNIX: u64 = 1;
    const WINDOWS: u64 = 0;

    let unix_host_name = if cfg!(unix) {
        br"sub\nam.t".as_slice()
    } else {
        b"sub_nam.t".as_slice()
    };
    let unix_host_path = if cfg!(unix) {
        std::path::Path::new(r"sub\nam.t")
    } else {
        std::path::Path::new("sub_nam.t")
    };
    assert_eq!(rar50_entry_name(br"sub\nam.t", UNIX), unix_host_name);
    assert_eq!(
        rar50_entry_name(br"sub\nam.t", WINDOWS),
        b"sub_nam.t".to_vec()
    );

    assert_eq!(
        rar50_output_relative_path(br"sub\nam.t", UNIX).unwrap(),
        unix_host_path
    );
    assert_eq!(
        rar50_output_relative_path(br"sub\nam.t", WINDOWS).unwrap(),
        std::path::Path::new("sub_nam.t")
    );
    // Forward slashes still separate, whatever the host.
    assert_eq!(
        rar50_output_relative_path(b"dir/nam.t", UNIX).unwrap(),
        std::path::Path::new("dir/nam.t")
    );
    // RAR 1.5-4.x keeps the old meaning.
    assert_eq!(
        output_relative_path(br"sub\nam.t").unwrap(),
        std::path::Path::new("sub/nam.t")
    );
}

/// A literal or mapped backslash name stays within one component. Real
/// parent components must still be refused on every native platform.
#[test]
fn rar50_backslash_traversal_is_still_refused() {
    const UNIX: u64 = 1;
    const WINDOWS: u64 = 0;
    let mapped = rar50_output_relative_path(br"..\..\pwn", UNIX).unwrap();
    assert_eq!(
        mapped,
        if cfg!(unix) {
            std::path::Path::new(r"..\..\pwn")
        } else {
            std::path::Path::new(".._.._pwn")
        }
    );
    assert_eq!(mapped.components().count(), 1);
    for host in [UNIX, WINDOWS] {
        for name in [b"../../pwn".as_slice(), br"../..\pwn", b"/pwn"] {
            assert!(rar50_output_relative_path(name, host).is_err());
        }
    }
    assert!(output_relative_path(br"..\..\pwn").is_err());
}

#[test]
fn restore_output_metadata_updates_file_and_directory_times() {
    let root = scratch("metadata-times");
    let file = root.join("payload.exe");
    let dir = root.join("nested");
    fs::write(&file, b"payload").unwrap();
    fs::create_dir(&dir).unwrap();

    let outputs = [
        ExtractedOutput {
            name: b"payload.exe".to_vec(),
            stored: std::path::PathBuf::new(),
            path: file,
            meta: ExtractedEntryMeta::new(
                b"payload.exe".to_vec(),
                Some(crate::Timestamp::from_unix_seconds(1_704_067_200)),
                0x20,
                false,
            ),
            restore_metadata: true,
            restore_mode: true,
            restore_time: true,
        },
        ExtractedOutput {
            name: b"nested".to_vec(),
            stored: std::path::PathBuf::new(),
            path: dir,
            meta: ExtractedEntryMeta::new(
                b"nested".to_vec(),
                Some(crate::Timestamp::from_unix_seconds(1_704_067_200)),
                0x10,
                true,
            ),
            restore_metadata: true,
            restore_mode: true,
            restore_time: true,
        },
    ];

    restore_output_metadata(&outputs).unwrap();
}

#[cfg(unix)]
#[test]
fn restore_directory_metadata_handles_restrictive_modes_in_any_entry_order() {
    use std::os::unix::fs::PermissionsExt;
    use std::time::{Duration, UNIX_EPOCH};

    let root = scratch("restrictive-directory-metadata");
    let paths = [
        root.join("parent"),
        root.join("parent/child"),
        root.join("parent/child/leaf"),
    ];
    for path in &paths {
        fs::create_dir(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    // Neither archive order nor its reverse is a safe finalization order.
    let outputs: Vec<_> = [0, 2, 1]
        .into_iter()
        .map(|index| {
            let name = paths[index]
                .file_name()
                .unwrap()
                .as_encoded_bytes()
                .to_vec();
            ExtractedOutput {
                name: name.clone(),
                stored: std::path::PathBuf::new(),
                path: paths[index].clone(),
                meta: ExtractedEntryMeta::new(
                    name,
                    Some(crate::Timestamp::from_unix_seconds(
                        1_704_067_200 + index as i64,
                    )),
                    0o040000,
                    true,
                )
                .with_attr_source(crate::AttrSource::Unix),
                restore_metadata: true,
                restore_mode: true,
                restore_time: true,
            }
        })
        .collect();

    let result = restore_output_metadata(&outputs);
    // Reopen parents before inspecting children, also allowing scratch cleanup
    // if metadata restoration failed halfway through.
    let mut metadata = Vec::new();
    for path in &paths {
        metadata.push(fs::metadata(path).unwrap());
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    result.unwrap();
    for (index, meta) in metadata.iter().enumerate() {
        assert_eq!(meta.permissions().mode() & 0o777, 0);
        assert_eq!(
            meta.modified().unwrap(),
            UNIX_EPOCH + Duration::from_secs(1_704_067_200 + index as u64)
        );
    }
}

#[test]
fn output_relative_path_accepts_plain_nested_names() {
    assert_eq!(
        output_relative_path(b"dir\\subdir/file.txt").unwrap(),
        Path::new("dir").join("subdir").join("file.txt")
    );
}

#[test]
fn output_relative_path_rejects_traversal_and_absolute_names() {
    for name in [
        b"../evil.txt".as_slice(),
        b"safe/../../evil.txt",
        b"/tmp/evil.txt",
        b"//server/share/evil.txt",
        b"\\server\\share\\evil.txt",
        b"C:/evil.txt",
        b"C:evil.txt",
        b"",
        b".",
        b"./.",
        b"bad\0name.txt",
    ] {
        assert!(output_relative_path(name).is_err(), "{name:?}");
    }
}

#[cfg(unix)]
#[test]
fn output_relative_path_preserves_non_utf8_archive_names() {
    use std::os::unix::ffi::OsStrExt;
    let path = output_relative_path(b"legacy-\xff-name.txt").unwrap();
    assert_eq!(path.as_os_str().as_bytes(), b"legacy-\xff-name.txt");
}

#[cfg(unix)]
#[test]
fn open_output_writer_rejects_existing_symlink_components() {
    let scratch = crate::scratch::case("rars-symlink-output");
    let root = scratch.join("root");
    let outside = scratch.join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::create_dir_all(&root).unwrap();
    std::os::unix::fs::symlink(&outside, root.join("link")).unwrap();
    assert!(matches!(
        checked_output_path(&root, Path::new("link").join("escape.txt").as_path()),
        Err(Error::UnsafePath("unsafe archive path crosses symlink"))
    ));
    assert!(!outside.join("escape.txt").exists());
}

fn write_settled(
    state: &mut ExtractEngine<'_>,
    meta: &crate::ExtractedEntryMeta,
    data: &[u8],
) -> crate::Result<()> {
    let written = state.open_settled(meta).and_then(|mut writer| {
        writer.write_all(data)?;
        Ok(())
    });
    state.settle(written.is_ok())?;
    written
}

#[cfg(unix)]
#[test]
fn a_directory_swapped_for_a_symlink_mid_extraction_is_never_written_through() {
    use std::io::Write;
    let policies = [
        OverwritePolicy::Never,
        OverwritePolicy::Always,
        OverwritePolicy::Rename,
    ];
    for planted in ["a", "a/b"] {
        for overwrite in policies {
            let scratch = crate::scratch::case("rars-planted-symlink");
            let root = scratch.join("out");
            let outside = scratch.join("outside");
            std::fs::create_dir_all(&outside).unwrap();
            let mut state = ExtractEngine::new(
                &root,
                overwrite,
                false,
                false,
                crate::ArchiveFamily::Rar50Plus,
            );
            let meta = |name: &str| {
                crate::ExtractedEntryMeta::new(name.as_bytes().to_vec(), None, 0, false)
            };
            write_settled(&mut state, &meta("a/b/one"), b"a/b/one").unwrap();
            let mut writer = state.open_settled(&meta("a/b/two")).unwrap();
            writer.write_all(b"a/b/two").unwrap();
            drop(writer);
            // `one` is in place and `two` is staged when the directory is swapped.
            state.publisher.wait();
            let moved = root.join("moved");
            std::fs::rename(root.join(planted), &moved).unwrap();
            std::os::unix::fs::symlink(&outside, root.join(planted)).unwrap();
            let finished = state
                .settle(true)
                .and_then(|_| write_settled(&mut state, &meta("a/b/three"), b"a/b/three"))
                .and_then(|()| state.publish().map(drop));

            let escaped: Vec<_> = std::fs::read_dir(&outside)
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect();
            assert!(escaped.is_empty(), "{planted} {overwrite:?}: {escaped:?}");
            if finished.is_ok() {
                // Written into the directory the extraction opened, wherever it went.
                let moved = if planted == "a" {
                    moved.join("b")
                } else {
                    moved
                };
                for name in ["one", "two", "three"] {
                    assert_eq!(
                        std::fs::read(moved.join(name)).unwrap(),
                        format!("a/b/{name}").into_bytes()
                    );
                }
            }
        }
    }
}

/// In place, each member is opened at its destination through the
/// directories the run opened. A directory swapped for a symlink
/// partway through is never written through: later members, in it or in
/// a new directory below it, land in the directory the run opened,
/// wherever it went.
#[cfg(unix)]
#[test]
fn a_directory_swapped_for_a_symlink_mid_extraction_in_place_is_never_written_through() {
    let policies = [
        OverwritePolicy::Never,
        OverwritePolicy::Always,
        OverwritePolicy::Rename,
    ];
    for planted in ["a", "a/b"] {
        for overwrite in policies {
            let scratch = crate::scratch::case("rars-planted-symlink-in-place");
            let root = scratch.join("out");
            let outside = scratch.join("outside");
            std::fs::create_dir_all(&outside).unwrap();
            let mut state = ExtractEngine::new(
                &root,
                overwrite,
                true,
                false,
                crate::ArchiveFamily::Rar50Plus,
            );
            let meta = |name: &str| {
                crate::ExtractedEntryMeta::new(name.as_bytes().to_vec(), None, 0, false)
            };
            let write = |state: &mut ExtractEngine, name: &str| {
                write_settled(state, &meta(name), name.as_bytes())
            };
            write(&mut state, "a/b/one").unwrap();
            write(&mut state, "a/b/two").unwrap();
            // Both are at their destinations when the directory is swapped.
            assert_eq!(std::fs::read(root.join("a/b/one")).unwrap(), b"a/b/one");
            let moved = root.join("moved");
            std::fs::rename(root.join(planted), &moved).unwrap();
            std::os::unix::fs::symlink(&outside, root.join(planted)).unwrap();
            let finished = write(&mut state, "a/b/three")
                .and_then(|()| write(&mut state, "a/b/c/four"))
                .and_then(|()| state.publish().map(drop));

            let context = format!("{planted} {overwrite:?}: {finished:?}");
            let escaped: Vec<_> = std::fs::read_dir(&outside)
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect();
            assert!(escaped.is_empty(), "{context}: {escaped:?}");
            assert!(finished.is_ok(), "{context}");
            let moved = if planted == "a" {
                moved.join("b")
            } else {
                moved
            };
            for name in ["one", "two", "three", "c/four"] {
                assert_eq!(
                    std::fs::read(moved.join(name)).unwrap(),
                    format!("a/b/{name}").into_bytes(),
                    "{context}"
                );
            }
        }
    }
}

/// In place, a member in a directory this run made is opened without
/// looking at its destination first. Something planted there after the
/// directory was made is never written through or over: `Never` and
/// `Always` refuse it as another member's output, `Rename` goes beside it.
#[cfg(unix)]
#[test]
fn an_entry_planted_where_a_member_goes_in_place_is_never_written_through() {
    let policies = [
        OverwritePolicy::Never,
        OverwritePolicy::Always,
        OverwritePolicy::Rename,
    ];
    for plant in ["symlink", "hard link", "file"] {
        for overwrite in policies {
            let scratch = crate::scratch::case("rars-planted-in-place");
            let root = scratch.join("out");
            let outside = scratch.join("outside");
            std::fs::create_dir_all(&outside).unwrap();
            std::fs::write(outside.join("target"), b"outside").unwrap();
            let mut state = ExtractEngine::new(
                &root,
                overwrite,
                true,
                false,
                crate::ArchiveFamily::Rar50Plus,
            );
            let meta = |name: &str| {
                crate::ExtractedEntryMeta::new(name.as_bytes().to_vec(), None, 0, false)
            };
            let write = |state: &mut ExtractEngine, name: &str| {
                write_settled(state, &meta(name), name.as_bytes())
            };
            write(&mut state, "d/one").unwrap();
            let planted = root.join("d/two");
            match plant {
                "symlink" => std::os::unix::fs::symlink(outside.join("target"), &planted).unwrap(),
                "hard link" => std::fs::hard_link(outside.join("target"), &planted).unwrap(),
                _ => std::fs::write(&planted, b"planted").unwrap(),
            }
            let finished = write(&mut state, "d/two").and_then(|()| state.publish().map(drop));

            let context = format!("{plant} {overwrite:?}: {finished:?}");
            assert_eq!(
                std::fs::read(outside.join("target")).unwrap(),
                b"outside",
                "{context}"
            );
            assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 1, "{context}");
            let found = std::fs::symlink_metadata(&planted).unwrap();
            assert_eq!(found.file_type().is_symlink(), plant == "symlink");
            if plant == "file" {
                assert_eq!(std::fs::read(&planted).unwrap(), b"planted", "{context}");
            }
            if overwrite == OverwritePolicy::Rename {
                assert!(finished.is_ok(), "{context}");
                assert_eq!(std::fs::read(root.join("d/two(1)")).unwrap(), b"d/two");
            } else {
                assert!(
                    matches!(
                        &finished,
                        Err(Error::InvalidHeader(
                            "multiple archive entries map to the same output path"
                        ))
                    ),
                    "{context}"
                );
                assert_eq!(std::fs::read_dir(root.join("d")).unwrap().count(), 2);
            }
            assert_eq!(std::fs::read(root.join("d/one")).unwrap(), b"d/one");
        }
    }
}

/// A member in a directory this run made is opened without looking at
/// its destination. Something planted there after the directory was made
/// is still never written through, and only `Always` replaces it.
#[cfg(unix)]
#[test]
fn an_entry_planted_in_a_directory_made_by_the_run_is_never_written_through() {
    let policies = [
        OverwritePolicy::Never,
        OverwritePolicy::Always,
        OverwritePolicy::Rename,
    ];
    for plant in ["symlink", "file"] {
        for overwrite in policies {
            let scratch = crate::scratch::case("rars-planted-in-made-directory");
            let root = scratch.join("out");
            let outside = scratch.join("outside");
            std::fs::create_dir_all(&outside).unwrap();
            std::fs::write(outside.join("target"), b"outside").unwrap();
            let mut state = ExtractEngine::new(
                &root,
                overwrite,
                false,
                false,
                crate::ArchiveFamily::Rar50Plus,
            );
            let meta = |name: &str| {
                crate::ExtractedEntryMeta::new(name.as_bytes().to_vec(), None, 0, false)
            };
            let write = |state: &mut ExtractEngine, name: &str| {
                write_settled(state, &meta(name), name.as_bytes())
            };
            // Opening `other` publishes `one`, which makes `d`.
            write(&mut state, "d/one").unwrap();
            write(&mut state, "d/other").unwrap();
            state.publisher.wait();
            assert_eq!(std::fs::read(root.join("d/one")).unwrap(), b"d/one");
            let planted = root.join("d/two");
            if plant == "symlink" {
                std::os::unix::fs::symlink(outside.join("target"), &planted).unwrap();
            } else {
                std::fs::write(&planted, b"planted").unwrap();
            }
            let finished = write(&mut state, "d/two").and_then(|()| state.publish().map(drop));

            let context = format!("{plant} {overwrite:?}: {finished:?}");
            assert_eq!(
                std::fs::read(outside.join("target")).unwrap(),
                b"outside",
                "{context}"
            );
            assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 1, "{context}");
            let found = std::fs::symlink_metadata(&planted).unwrap();
            match overwrite {
                OverwritePolicy::Never => {
                    assert!(
                        matches!(
                            &finished,
                            Err(Error::InvalidHeader(
                                "multiple archive entries map to the same output path"
                            ))
                        ),
                        "{context}"
                    );
                    assert_eq!(found.file_type().is_symlink(), plant == "symlink");
                    assert_eq!(std::fs::read_dir(root.join("d")).unwrap().count(), 3);
                }
                OverwritePolicy::Always => {
                    assert!(finished.is_ok(), "{context}");
                    assert!(found.file_type().is_file(), "{context}");
                    assert_eq!(std::fs::read(&planted).unwrap(), b"d/two");
                }
                OverwritePolicy::Rename => {
                    assert!(finished.is_ok(), "{context}");
                    assert_eq!(found.file_type().is_symlink(), plant == "symlink");
                    let renamed: Vec<_> = std::fs::read_dir(root.join("d"))
                        .unwrap()
                        .map(|entry| entry.unwrap().file_name())
                        .filter(|name| name.to_string_lossy().starts_with("two"))
                        .collect();
                    assert_eq!(renamed.len(), 2, "{context}: {renamed:?}");
                    let ours = renamed.iter().find(|name| *name != "two").unwrap();
                    assert_eq!(std::fs::read(root.join("d").join(ours)).unwrap(), b"d/two");
                }
            }
            assert_eq!(std::fs::read(root.join("d/other")).unwrap(), b"d/other");
        }
    }
}

#[test]
fn never_refuses_with_the_hint_when_one_is_given() {
    let root = scratch("exists-hint");
    fs::write(root.join("taken"), b"keep").unwrap();
    for (hint, expected) in [
        (None, "File exists"),
        (Some("; try Rename"), "already exists; try Rename"),
    ] {
        let mut state = ExtractEngine::new(
            &root,
            OverwritePolicy::Never,
            false,
            false,
            ArchiveFamily::Rar50Plus,
        );
        if let Some(hint) = hint {
            state.exists_hint(hint);
        }
        let error = state
            .open_settled(&ExtractedEntryMeta::new(b"taken".to_vec(), None, 0, false))
            .err()
            .unwrap();
        assert!(error.to_string().contains(expected), "{error}");
    }
    assert_eq!(fs::read(root.join("taken")).unwrap(), b"keep");
}

#[cfg(unix)]
#[test]
fn a_directory_with_no_time_keeps_its_old_one_unless_told_to_leave_it() {
    let old = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000_000);
    for keep in [true, false] {
        let root = scratch("directory-time");
        fs::create_dir(root.join("dir")).unwrap();
        fs::File::open(root.join("dir"))
            .unwrap()
            .set_modified(old)
            .unwrap();
        let mut state = ExtractEngine::new(
            &root,
            OverwritePolicy::Always,
            false,
            false,
            ArchiveFamily::Rar50Plus,
        );
        if !keep {
            state.leave_directory_time();
        }
        for (name, directory) in [("dir", true), ("dir/file", false)] {
            let meta = ExtractedEntryMeta::new(name.as_bytes().to_vec(), None, 0, directory);
            state.open_settled(&meta).unwrap();
            state.settle(true).unwrap();
        }
        let outputs = state.publish().unwrap();
        restore_output_metadata(&outputs).unwrap();
        let modified = fs::metadata(root.join("dir")).unwrap().modified().unwrap();
        assert_eq!(modified == old, keep);
    }
}

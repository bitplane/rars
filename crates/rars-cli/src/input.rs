use crate::password::Password;
use crate::time::{source_dos_mtime, source_unix_mtime};
use crate::{CliResult, DOS_ARCHIVE_ATTR};
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use zeroize::Zeroizing;

/// An input read fully into memory, for the RAR 1.3 and RAR 1.5-4.x writers.
/// Those formats record DOS timestamps, so the Unix one is not carried here.
pub(crate) struct OwnedInput {
    pub(crate) name: Vec<u8>,
    pub(crate) data: Vec<u8>,
    pub(crate) file_attr: u8,
    pub(crate) unix_mode: Option<u32>,
    pub(crate) dos_mtime: u32,
    pub(crate) password: Option<Password>,
}

pub(crate) struct LazyInput {
    pub(crate) path: PathBuf,
    pub(crate) name: Vec<u8>,
    pub(crate) size: u64,
    pub(crate) file_attr: u8,
    pub(crate) unix_mode: Option<u32>,
    pub(crate) unix_mtime: Option<u32>,
    pub(crate) dos_mtime: u32,
}

pub(crate) fn collect_inputs(paths: &[PathBuf]) -> CliResult<Vec<LazyInput>> {
    let mut pending = Vec::new();
    for path in paths {
        let path = Path::new(path);
        let base = input_archive_base(path)?;
        collect_input(path, &base, &mut pending)?;
    }
    if pending.is_empty() {
        return Err("no regular input files found".into());
    }
    reject_duplicate_input_names(pending.iter().map(|entry| entry.name.as_slice()))?;
    Ok(pending)
}

pub(crate) fn read_inputs_with_progress<F, G>(
    paths: &[PathBuf],
    password: Option<&[u8]>,
    discovered: F,
    mut advanced: G,
) -> CliResult<Vec<OwnedInput>>
where
    F: FnOnce(usize, u64),
    G: FnMut(u64, &[u8]),
{
    let pending = collect_inputs(paths)?;
    discovered(pending.len(), pending.iter().map(|entry| entry.size).sum());
    let mut out = Vec::with_capacity(pending.len());
    for entry in pending {
        let data =
            read_file_with_progress(&entry.path, "input", |bytes| advanced(bytes, &entry.name))?;
        out.push(OwnedInput {
            name: entry.name,
            data,
            file_attr: entry.file_attr,
            unix_mode: entry.unix_mode,
            dos_mtime: entry.dos_mtime,
            password: password.map(|p| Zeroizing::new(p.to_vec())),
        });
    }
    Ok(out)
}

fn collect_input(path: &Path, archive_name: &Path, out: &mut Vec<LazyInput>) -> CliResult<()> {
    let meta = fs::symlink_metadata(path)
        .map_err(|err| format!("failed to stat input '{}': {err}", path.display()))?;
    if meta.file_type().is_symlink() {
        return Err(format!(
            "input '{}' is a symlink; refusing to follow it",
            path.display()
        )
        .into());
    }
    if meta.is_dir() {
        let mut children = fs::read_dir(path)
            .map_err(|err| format!("failed to read directory '{}': {err}", path.display()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| format!("failed to read directory '{}': {err}", path.display()))?;
        children.sort_by_key(|entry| entry.file_name());
        for child in children {
            let child_path = child.path();
            let child_name = archive_name.join(child.file_name());
            collect_input(&child_path, &child_name, out)?;
        }
    } else if meta.is_file() {
        let unix_mtime = source_unix_mtime(&meta);
        let dos_mtime = source_dos_mtime(&meta);
        let unix_mode = source_unix_mode(&meta);
        let name = archive_path_bytes(archive_name)?;
        out.push(LazyInput {
            path: path.to_path_buf(),
            name,
            size: meta.len(),
            file_attr: DOS_ARCHIVE_ATTR,
            unix_mode,
            unix_mtime,
            dos_mtime,
        });
    } else {
        return Err(format!("input '{}' is not a regular file", path.display()).into());
    }
    Ok(())
}

fn input_archive_base(path: &Path) -> CliResult<PathBuf> {
    if path.is_absolute() {
        return path
            .file_name()
            .map(PathBuf::from)
            .ok_or_else(|| "input path has no file name".into());
    }
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => out.push(part),
            Component::CurDir => {}
            _ => return Err(format!("unsafe input archive path: {}", path.display()).into()),
        }
    }
    if out.as_os_str().is_empty() {
        return Err("input path has no file name".into());
    }
    Ok(out)
}

// Called only with a nonempty base validated by input_archive_base, followed by
// filesystem child names. All components are normal; revalidating here is redundant.
fn archive_path_bytes(path: &Path) -> CliResult<Vec<u8>> {
    let parts = path
        .components()
        .map(|component| rars::filename::native_bytes(component.as_os_str()))
        .collect::<rars::Result<Vec<_>>>()?;
    Ok(parts.join(&b'/'))
}

fn reject_duplicate_input_names<'a>(entries: impl IntoIterator<Item = &'a [u8]>) -> CliResult<()> {
    let mut seen = HashSet::new();
    for entry in entries {
        if !seen.insert(entry.to_vec()) {
            return Err(format!(
                "multiple input entries map to archive name '{}'",
                String::from_utf8_lossy(entry)
            )
            .into());
        }
    }
    Ok(())
}

fn read_file_with_progress(
    path: &Path,
    role: &str,
    mut advanced: impl FnMut(u64),
) -> CliResult<Vec<u8>> {
    let mut file = File::open(path)
        .map_err(|err| format!("failed to read {role} '{}': {err}", path.display()))?;
    let mut data = Vec::new();
    let mut buffer = vec![0; 1024 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|err| format!("failed to read {role} '{}': {err}", path.display()))?;
        if read == 0 {
            break;
        }
        data.extend_from_slice(&buffer[..read]);
        advanced(read as u64);
    }
    Ok(data)
}

#[cfg(unix)]
fn source_unix_mode(metadata: &fs::Metadata) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;

    Some(metadata.permissions().mode())
}

#[cfg(not(unix))]
fn source_unix_mode(_metadata: &fs::Metadata) -> Option<u32> {
    None
}

/// The attribute word the RAR 1.5+ writers record, preferring the Unix mode
/// where there is one.
pub(crate) fn rar15_file_attr(unix_mode: Option<u32>, file_attr: u8) -> u32 {
    unix_mode.unwrap_or_else(|| u32::from(file_attr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collection_rejects_empty_unsafe_missing_and_duplicate_inputs() {
        let root = crate::scratch::case("input-collection-errors");
        let empty = root.join("empty");
        fs::create_dir(&empty).unwrap();
        for paths in [vec![], vec![empty]] {
            assert_eq!(
                collect_inputs(&paths).err().unwrap().to_string(),
                "no regular input files found"
            );
        }
        for path in ["", ".", "./"] {
            assert_eq!(
                collect_inputs(&[PathBuf::from(path)])
                    .err()
                    .unwrap()
                    .to_string(),
                "input path has no file name"
            );
        }
        for path in ["../file", "dir/../file"] {
            assert!(collect_inputs(&[PathBuf::from(path)])
                .err()
                .unwrap()
                .to_string()
                .contains("unsafe input archive path"));
        }
        assert_eq!(
            input_archive_base(Path::new("./dir/./file")).unwrap(),
            Path::new("dir/file")
        );
        assert!(collect_inputs(&[root.join("missing")])
            .err()
            .unwrap()
            .to_string()
            .contains("failed to stat input"));
        for parent in ["one", "two"] {
            fs::create_dir(root.join(parent)).unwrap();
            fs::write(root.join(parent).join("same"), parent).unwrap();
        }
        let error = collect_inputs(&[root.join("one/same"), root.join("two/same")])
            .err()
            .unwrap();
        assert_eq!(
            error.to_string(),
            "multiple input entries map to archive name 'same'"
        );
        assert_eq!(
            rar15_file_attr(None, DOS_ARCHIVE_ATTR),
            u32::from(DOS_ARCHIVE_ATTR)
        );
        assert_eq!(rar15_file_attr(Some(0o100640), DOS_ARCHIVE_ATTR), 0o100640);
    }

    #[test]
    fn validation_failure_does_not_emit_discovery_or_progress() {
        let error = read_inputs_with_progress(
            &[],
            None,
            |_, _| panic!("invalid inputs must not emit discovery"),
            |_, _| panic!("invalid inputs must not emit progress"),
        )
        .err()
        .unwrap();
        assert_eq!(error.to_string(), "no regular input files found");
        #[cfg(unix)]
        assert_eq!(
            input_archive_base(Path::new("/")).unwrap_err().to_string(),
            "input path has no file name"
        );
        for (path, name) in [
            ("./dir/./file", b"dir/file".as_slice()),
            ("name", b"name".as_slice()),
        ] {
            let base = input_archive_base(Path::new(path)).unwrap();
            assert_eq!(archive_path_bytes(&base).unwrap(), name);
        }
    }

    #[cfg(unix)]
    #[test]
    fn unreadable_directory_error_names_the_source() {
        use std::os::unix::fs::PermissionsExt;
        let root = crate::scratch::case("input-unreadable-directory");
        let input = root.join("unreadable");
        fs::create_dir(&input).unwrap();
        fs::write(input.join("file"), b"payload").unwrap();
        let original = fs::metadata(&input).unwrap().permissions();
        fs::set_permissions(&input, fs::Permissions::from_mode(0o0)).unwrap();
        // Privileged runners may bypass permission bits; restore before returning
        // or asserting so the scratch directory remains removable in either case.
        let permission_bits_enforced = fs::read_dir(&input).is_err();
        let result = collect_inputs(std::slice::from_ref(&input));
        fs::set_permissions(&input, original).unwrap();
        if !permission_bits_enforced {
            eprintln!("permission-denial case unavailable on this privileged runner");
            return;
        }
        let error = result.err().unwrap().to_string();
        assert!(error.contains("failed to read directory"));
        assert!(error.contains(&input.display().to_string()));
    }

    #[test]
    fn reads_sorted_inputs_with_exact_progress_contents_and_passwords() {
        use std::cell::RefCell;
        let root = crate::scratch::case("input-progress-contents");
        let input = root.join("input");
        fs::create_dir_all(input.join("nested")).unwrap();
        fs::write(input.join("a-empty"), []).unwrap();
        let payload: Vec<_> = (0..1024 * 1024 + 17).map(|n| (n % 251) as u8).collect();
        fs::write(input.join("nested/z-data"), &payload).unwrap();
        let lazy = collect_inputs(std::slice::from_ref(&input)).unwrap();
        let events = RefCell::new(Vec::new());
        let owned = read_inputs_with_progress(
            std::slice::from_ref(&input),
            Some(b"secret"),
            |count, bytes| {
                assert_eq!((count, bytes), (2, payload.len() as u64));
                events.borrow_mut().push((bytes, Vec::new()));
            },
            |bytes, name| events.borrow_mut().push((bytes, name.to_vec())),
        )
        .unwrap();
        assert_eq!(owned.len(), 2);
        assert_eq!(owned[0].name, b"input/a-empty");
        assert!(owned[0].data.is_empty());
        assert_eq!(owned[1].name, b"input/nested/z-data");
        assert_eq!(owned[1].data, payload);
        for (owned, lazy) in owned.iter().zip(lazy) {
            assert_eq!(owned.name, lazy.name);
            assert_eq!(owned.file_attr, DOS_ARCHIVE_ATTR);
            assert_eq!(owned.unix_mode, lazy.unix_mode);
            assert_eq!(owned.dos_mtime, lazy.dos_mtime);
            assert_eq!(owned.password.as_deref().unwrap().as_slice(), b"secret");
        }
        let events = events.into_inner();
        assert!(events.len() >= 3);
        assert_eq!(
            events[1..].iter().map(|event| event.0).sum::<u64>(),
            payload.len() as u64
        );
        assert!(events[1..]
            .iter()
            .all(|event| event.0 > 0 && event.1 == b"input/nested/z-data"));
        let without_password =
            read_inputs_with_progress(&[input.join("a-empty")], None, |_, _| {}, |_, _| {})
                .unwrap();
        assert!(without_password[0].password.is_none());
    }

    #[test]
    fn read_failure_after_discovery_is_reported_without_success_progress() {
        let root = crate::scratch::case("input-disappears-after-discovery");
        let input = root.join("file");
        fs::write(&input, b"payload").unwrap();
        let error = read_inputs_with_progress(
            std::slice::from_ref(&input),
            None,
            |count, size| {
                assert_eq!((count, size), (1, 7));
                fs::remove_file(&input).unwrap();
            },
            |_, _| panic!("failed read must not report successful bytes"),
        )
        .err()
        .unwrap();
        assert!(error.to_string().contains("failed to read input"));
        #[cfg(unix)]
        {
            let error =
                read_file_with_progress(&root, "input", |_| panic!("directory read must fail"))
                    .unwrap_err();
            assert!(error.to_string().contains("failed to read input"));
        }
    }

    #[cfg(unix)]
    #[test]
    fn collection_refuses_symlinks_and_special_files_before_reading() {
        use std::os::unix::fs::symlink;
        let root = crate::scratch::case("input-special-files");
        let target = root.join("target");
        fs::write(&target, b"payload").unwrap();
        let link = root.join("link");
        symlink(&target, &link).unwrap();
        assert!(collect_inputs(&[link])
            .err()
            .unwrap()
            .to_string()
            .contains("is a symlink"));
        let directory = root.join("directory");
        fs::create_dir(&directory).unwrap();
        symlink(&target, directory.join("child")).unwrap();
        assert!(collect_inputs(&[directory])
            .err()
            .unwrap()
            .to_string()
            .contains("is a symlink"));
        let fifo = root.join("fifo");
        let status = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap();
        assert!(status.success());
        let error = collect_inputs(&[fifo])
            .err()
            .expect("FIFO must be rejected without opening it");
        assert!(error.to_string().contains("is not a regular file"));
        let error = collect_inputs(&[PathBuf::from("/dev/null")])
            .err()
            .expect("special files must be rejected during collection");
        assert!(error.to_string().contains("is not a regular file"));
    }

    #[cfg(unix)]
    #[test]
    fn collect_inputs_preserves_non_utf8_child_names() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let root = crate::scratch::case("cli-non-utf8-name");
        let input = root.join("input");
        fs::create_dir(&input).unwrap();
        fs::write(input.join(OsStr::from_bytes(b"bad-\xff")), b"payload").unwrap();
        let entries = collect_inputs(&[input]).unwrap();
        assert_eq!(entries[0].name, b"input/bad-\xff");
        assert_eq!(fs::read(&entries[0].path).unwrap(), b"payload");
    }

    #[test]
    fn collect_inputs_preserves_unicode_names_and_source_paths() {
        let root = crate::scratch::case("cli-unicode-names");
        let input = root.join("input");
        fs::create_dir_all(input.join("日本語")).unwrap();
        let mut names = ["日本語", "кириллица", "replacement-\u{fffd}"];
        for name in names {
            fs::write(input.join("日本語").join(name), name.as_bytes()).unwrap();
        }
        names.sort();
        let entries = collect_inputs(std::slice::from_ref(&input)).unwrap();
        assert_eq!(entries.len(), names.len());
        for (entry, name) in entries.iter().zip(names) {
            assert_eq!(entry.name, format!("input/日本語/{name}").as_bytes());
            assert_eq!(entry.path, input.join("日本語").join(name));
            assert_eq!(fs::read(&entry.path).unwrap(), name.as_bytes());
        }
    }
}

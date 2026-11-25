use crate::{CliResult, DOS_ARCHIVE_ATTR};
use std::collections::HashSet;
use std::fs;
use std::path::{Component, Path, PathBuf};

pub(crate) struct LazyInput {
    pub(crate) is_directory: bool,
    pub(crate) path: PathBuf,
    pub(crate) name: Vec<u8>,
    pub(crate) size: u64,
    pub(crate) file_attr: u8,
    pub(crate) unix_mode: Option<u32>,
    /// Whole seconds: the writers below store no finer.
    pub(crate) mtime: Option<rars::Timestamp>,
}

/// An input's time as each family's writer stores it.
pub(crate) trait StoredTime {
    fn mtime(&self) -> Option<rars::Timestamp>;

    /// RAR 1.3–4.x: a DOS time, or 0 where the file's time doesn't fit.
    fn dos_time(&self) -> u32 {
        self.mtime()
            .and_then(rars::timestamp::dos_time)
            .unwrap_or(0)
    }

    /// RAR5/7: Unix seconds, where they fit the 32-bit field.
    fn unix_seconds(&self) -> Option<u32> {
        self.mtime()
            .and_then(|time| u32::try_from(time.unix_seconds()).ok())
    }
}

impl StoredTime for LazyInput {
    fn mtime(&self) -> Option<rars::Timestamp> {
        self.mtime
    }
}

impl LazyInput {
    pub(crate) fn source(&self) -> rars::EntrySource {
        if self.is_directory {
            rars::EntrySource::from_bytes(Vec::new())
        } else {
            rars::EntrySource::from_path(self.path.clone())
        }
    }
}

pub(crate) fn collect_inputs(
    paths: &[PathBuf],
    base_dir: Option<&Path>,
) -> CliResult<Vec<LazyInput>> {
    if let Some(base) = base_dir {
        let meta = fs::metadata(base)
            .map_err(|err| format!("failed to stat base directory '{}': {err}", base.display()))?;
        if !meta.is_dir() {
            return Err(format!("base path '{}' is not a directory", base.display()).into());
        }
    }
    let mut pending = Vec::new();
    for path in paths {
        if base_dir.is_some() && path.is_absolute() {
            return Err(format!(
                "inputs must be relative when --base-dir is given: '{}'",
                path.display()
            )
            .into());
        }
        let archive_name = input_archive_base(path)?;
        let source = base_dir.map(|base| base.join(path));
        collect_input(
            source.as_deref().unwrap_or(path),
            &archive_name,
            &mut pending,
        )?;
    }
    if pending.is_empty() {
        return Err("no input files or directories found".into());
    }
    reject_duplicate_input_names(pending.iter().map(|entry| entry.name.as_slice()))?;
    Ok(pending)
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
    if meta.is_dir() || meta.is_file() {
        out.push(LazyInput {
            is_directory: meta.is_dir(),
            path: path.to_path_buf(),
            name: archive_path_bytes(archive_name)?,
            size: if meta.is_dir() { 0 } else { meta.len() },
            file_attr: if meta.is_dir() {
                0x10
            } else {
                DOS_ARCHIVE_ATTR
            },
            unix_mode: source_unix_mode(&meta),
            mtime: meta
                .modified()
                .ok()
                .and_then(|time| rars::Timestamp::try_from(time).ok())
                .map(|time| rars::Timestamp::from_unix_seconds(time.unix_seconds())),
        });
    } else {
        return Err(format!(
            "input '{}' is not a regular file or directory",
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
    fn collection_refuses_absolute_inputs_with_a_base() {
        let root = crate::scratch::case("input-absolute-with-base");
        let input = root.join("file");
        fs::write(&input, b"payload").unwrap();
        let error = collect_inputs(&[input], Some(&root)).err().unwrap();
        assert!(error
            .to_string()
            .contains("inputs must be relative when --base-dir is given"));
    }

    #[test]
    fn collection_uses_relative_names_with_a_base() {
        let root = crate::scratch::case("input-relative-with-base");
        let input = root.join("dir/file");
        fs::create_dir(root.join("dir")).unwrap();
        fs::write(&input, b"payload").unwrap();
        let entries = collect_inputs(&[PathBuf::from("./dir/./file")], Some(&root)).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, b"dir/file");
        assert_eq!(entries[0].path, input);
    }

    #[test]
    fn collection_rejects_empty_unsafe_missing_and_duplicate_inputs() {
        let root = crate::scratch::case("input-collection-errors");
        assert_eq!(
            collect_inputs(&[], None).err().unwrap().to_string(),
            "no input files or directories found"
        );
        for path in ["", ".", "./"] {
            assert_eq!(
                collect_inputs(&[PathBuf::from(path)], None)
                    .err()
                    .unwrap()
                    .to_string(),
                "input path has no file name"
            );
        }
        for path in ["../file", "dir/../file"] {
            assert!(collect_inputs(&[PathBuf::from(path)], None)
                .err()
                .unwrap()
                .to_string()
                .contains("unsafe input archive path"));
        }
        assert_eq!(
            input_archive_base(Path::new("./dir/./file")).unwrap(),
            Path::new("dir/file")
        );
        assert!(collect_inputs(&[root.join("missing")], None)
            .err()
            .unwrap()
            .to_string()
            .contains("failed to stat input"));
        for parent in ["one", "two"] {
            fs::create_dir(root.join(parent)).unwrap();
            fs::write(root.join(parent).join("same"), parent).unwrap();
        }
        let error = collect_inputs(&[root.join("one/same"), root.join("two/same")], None)
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
    fn validation_failure_names_what_was_wrong() {
        let error = collect_inputs(&[], None).err().unwrap();
        assert_eq!(error.to_string(), "no input files or directories found");
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
        let result = collect_inputs(std::slice::from_ref(&input), None);
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
    fn collects_inputs_sorted_with_their_sizes_and_attributes() {
        let root = crate::scratch::case("input-collection-order");
        let input = root.join("input");
        fs::create_dir_all(input.join("nested")).unwrap();
        fs::write(input.join("a-empty"), []).unwrap();
        fs::write(input.join("nested/z-data"), [7; 17]).unwrap();
        let inputs = collect_inputs(std::slice::from_ref(&input), None).unwrap();
        let seen: Vec<_> = inputs
            .iter()
            .map(|entry| (entry.name.as_slice(), entry.size, entry.file_attr))
            .collect();
        assert_eq!(
            seen,
            [
                (b"input".as_slice(), 0, 0x10),
                (b"input/a-empty".as_slice(), 0, DOS_ARCHIVE_ATTR),
                (b"input/nested".as_slice(), 0, 0x10),
                (b"input/nested/z-data".as_slice(), 17, DOS_ARCHIVE_ATTR),
            ]
        );
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
        assert!(collect_inputs(&[link], None)
            .err()
            .unwrap()
            .to_string()
            .contains("is a symlink"));
        let directory = root.join("directory");
        fs::create_dir(&directory).unwrap();
        symlink(&target, directory.join("child")).unwrap();
        assert!(collect_inputs(&[directory], None)
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
        let error = collect_inputs(&[fifo], None)
            .err()
            .expect("FIFO must be rejected without opening it");
        assert!(error.to_string().contains("is not a regular file"));
        let error = collect_inputs(&[PathBuf::from("/dev/null")], None)
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
        if !crate::scratch::supports_raw_byte_names(&root) {
            // The filesystem rejects this input before the CLI can collect it.
            assert!(fs::write(input.join(OsStr::from_bytes(b"bad-\xff")), b"payload").is_err());
            assert_eq!(collect_inputs(&[input], None).unwrap().len(), 1);
            return;
        }
        fs::write(input.join(OsStr::from_bytes(b"bad-\xff")), b"payload").unwrap();
        let entries = collect_inputs(&[input], None).unwrap();
        assert_eq!(entries[1].name, b"input/bad-\xff");
        assert_eq!(fs::read(&entries[1].path).unwrap(), b"payload");
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
        let entries = collect_inputs(std::slice::from_ref(&input), None).unwrap();
        assert_eq!(entries.len(), names.len() + 2);
        assert!(entries[0].is_directory);
        assert!(entries[1].is_directory);
        for (entry, name) in entries[2..].iter().zip(names) {
            assert_eq!(entry.name, format!("input/日本語/{name}").as_bytes());
            assert_eq!(entry.path, input.join("日本語").join(name));
            assert_eq!(fs::read(&entry.path).unwrap(), name.as_bytes());
        }
    }
}

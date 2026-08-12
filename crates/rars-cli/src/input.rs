use crate::password::Password;
use crate::time::{source_dos_mtime, source_unix_mtime};
use crate::{CliResult, DOS_ARCHIVE_ATTR};
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use zeroize::Zeroizing;

pub(crate) struct OwnedInput {
    pub(crate) name: Vec<u8>,
    pub(crate) data: Vec<u8>,
    pub(crate) file_attr: u8,
    pub(crate) unix_mode: Option<u32>,
    pub(crate) unix_mtime: Option<u32>,
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

pub(crate) fn collect_inputs(paths: &[String]) -> CliResult<Vec<LazyInput>> {
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
    paths: &[String],
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
            unix_mtime: entry.unix_mtime,
            dos_mtime: entry.dos_mtime,
            password: password.map(|p| Zeroizing::new(p.to_vec())),
        });
    }
    Ok(out)
}

fn collect_input(path: &Path, archive_name: &Path, out: &mut Vec<LazyInput>) -> CliResult<()> {
    let link_meta = fs::symlink_metadata(path)
        .map_err(|err| format!("failed to stat input '{}': {err}", path.display()))?;
    if link_meta.file_type().is_symlink() {
        return Err(format!(
            "input '{}' is a symlink; refusing to follow it",
            path.display()
        )
        .into());
    }
    let meta = fs::metadata(path)
        .map_err(|err| format!("failed to stat input '{}': {err}", path.display()))?;
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
    } else {
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

fn archive_path_bytes(path: &Path) -> CliResult<Vec<u8>> {
    let mut parts = Vec::new();
    for component in path.components() {
        let Component::Normal(part) = component else {
            return Err(format!("unsafe input archive path: {}", path.display()).into());
        };
        parts.push(part.to_string_lossy().into_owned());
    }
    if parts.is_empty() {
        return Err("input path has no file name".into());
    }
    Ok(parts.join("/").into_bytes())
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

pub(crate) fn rar15_file_attr(entry: &OwnedInput) -> u32 {
    entry
        .unix_mode
        .unwrap_or_else(|| u32::from(entry.file_attr))
}

pub(crate) fn rar50_file_attr(entry: &OwnedInput) -> u64 {
    u64::from(
        entry
            .unix_mode
            .unwrap_or_else(|| u32::from(entry.file_attr)),
    )
}

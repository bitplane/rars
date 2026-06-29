use crate::time::extracted_system_time;
use crate::{CliError, CliResult};
use rars::{Archive as DetectedArchive, ArchiveFamily, ArchiveVersion, Error, ExtractedEntryMeta};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::path::{Component, Path, PathBuf};
use std::time::SystemTime;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OverwritePolicy {
    Never,
    Always,
}

pub(crate) struct ExtractedOutput {
    pub(crate) name: Vec<u8>,
    pub(crate) path: PathBuf,
    pub(crate) meta: ExtractedEntryMeta,
    pub(crate) family: ArchiveFamily,
    pub(crate) restore_metadata: bool,
}

const FSREDIR_UNIX_SYMLINK: u64 = 0x01;
const FSREDIR_WINDOWS_SYMLINK: u64 = 0x02;
const FSREDIR_WINDOWS_JUNCTION: u64 = 0x03;
const FSREDIR_HARDLINK: u64 = 0x04;
const FSREDIR_FILE_COPY: u64 = 0x05;
#[cfg(windows)]
const FHEXTRA_REDIR_DIR: u64 = 0x01;

pub(crate) fn open_output_writer(
    out_dir: &Path,
    entry: &ExtractedEntryMeta,
    overwrite: OverwritePolicy,
) -> rars::Result<(PathBuf, Box<dyn std::io::Write>)> {
    let mut out_path = output_path_for_entry(out_dir, entry)?;
    if entry.is_directory {
        fs::create_dir_all(&out_path)?;
        return Ok((out_path, Box::new(std::io::sink())));
    }
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let rel = output_relative_path(&entry.name)
        .map_err(|_| Error::InvalidHeader("unsafe archive path"))?;
    out_path = checked_output_path(out_dir, &rel)?;
    Ok((
        out_path.clone(),
        Box::new(create_output_file(&out_path, overwrite)?),
    ))
}

pub(crate) fn output_path_for_entry(
    out_dir: &Path,
    entry: &ExtractedEntryMeta,
) -> rars::Result<PathBuf> {
    let rel = output_relative_path(&entry.name)
        .map_err(|_| Error::InvalidHeader("unsafe archive path"))?;
    checked_output_path(out_dir, &rel)
}

pub(crate) fn output_path_for_rar50_entry(
    out_dir: &Path,
    entry: &rars::rar50::ExtractedEntryMeta,
) -> rars::Result<PathBuf> {
    let rel = output_relative_path(&entry.name)
        .map_err(|_| Error::InvalidHeader("unsafe archive path"))?;
    checked_output_path(out_dir, &rel)
}

pub(crate) fn create_rar50_redirection(
    out_dir: &Path,
    entry: &rars::rar50::ExtractedEntryMeta,
    redirection: &rars::rar50::FileRedirection,
    overwrite: OverwritePolicy,
    created_paths: &HashMap<PathBuf, PathBuf>,
) -> rars::Result<(PathBuf, bool)> {
    let mut out_path = output_path_for_rar50_entry(out_dir, entry)?;
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let rel = output_relative_path(&entry.name)
        .map_err(|_| Error::InvalidHeader("unsafe archive path"))?;
    out_path = checked_output_path(out_dir, &rel)?;
    prepare_redirection_destination(&out_path, overwrite)?;

    match redirection.redirection_type {
        FSREDIR_UNIX_SYMLINK | FSREDIR_WINDOWS_SYMLINK | FSREDIR_WINDOWS_JUNCTION => {
            let target_rel = output_relative_path(&redirection.target_name)
                .map_err(|_| Error::InvalidHeader("unsafe archive redirection target"))?;
            create_symlink_redirection(&target_rel, &out_path, redirection.flags)?;
            Ok((out_path, false))
        }
        FSREDIR_HARDLINK => {
            let source = redirection_source_path(redirection, created_paths)?;
            fs::hard_link(source, &out_path)?;
            Ok((out_path, true))
        }
        FSREDIR_FILE_COPY => {
            let source = redirection_source_path(redirection, created_paths)?;
            fs::copy(source, &out_path)?;
            Ok((out_path, true))
        }
        _ => Err(Error::UnsupportedFeature {
            version: ArchiveVersion::Rar50,
            feature: "RAR 5 unsupported file redirection type",
        }),
    }
}

fn redirection_source_path<'a>(
    redirection: &rars::rar50::FileRedirection,
    created_paths: &'a HashMap<PathBuf, PathBuf>,
) -> rars::Result<&'a Path> {
    let target = output_relative_path(&redirection.target_name)
        .map_err(|_| Error::InvalidHeader("unsafe archive redirection target"))?;
    created_paths
        .get(&target)
        .map(PathBuf::as_path)
        .ok_or(Error::InvalidHeader(
            "RAR 5 redirection target was not extracted earlier",
        ))
}

fn prepare_redirection_destination(path: &Path, overwrite: OverwritePolicy) -> std::io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => match overwrite {
            OverwritePolicy::Never => Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "file exists",
            )),
            OverwritePolicy::Always => {
                if metadata.is_dir() && !metadata.file_type().is_symlink() {
                    fs::remove_dir(path)
                } else {
                    fs::remove_file(path)
                }
            }
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(unix)]
fn create_symlink_redirection(target: &Path, link: &Path, _flags: u64) -> std::io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

#[cfg(windows)]
fn create_symlink_redirection(target: &Path, link: &Path, flags: u64) -> std::io::Result<()> {
    if flags & FHEXTRA_REDIR_DIR != 0 {
        std::os::windows::fs::symlink_dir(target, link)
    } else {
        std::os::windows::fs::symlink_file(target, link)
    }
}

#[cfg(not(any(unix, windows)))]
fn create_symlink_redirection(_target: &Path, _link: &Path, _flags: u64) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "symbolic links are not supported on this platform",
    ))
}

pub(crate) fn restore_output_metadata(outputs: &[ExtractedOutput]) -> std::io::Result<()> {
    for output in outputs
        .iter()
        .filter(|output| output.restore_metadata && !output.meta.is_directory)
    {
        if let Some(time) = extracted_system_time(output.family, output.meta.file_time) {
            set_modified_time(&output.path, time)?;
        }
        set_extracted_permissions(&output.path, output.meta.file_attr)?;
    }
    for output in outputs
        .iter()
        .filter(|output| output.restore_metadata && output.meta.is_directory)
    {
        set_extracted_permissions(&output.path, output.meta.file_attr)?;
        if let Some(time) = extracted_system_time(output.family, output.meta.file_time) {
            set_modified_time(&output.path, time)?;
        }
    }
    Ok(())
}

fn set_modified_time(path: &Path, time: SystemTime) -> std::io::Result<()> {
    File::open(path)?.set_modified(time)
}

#[cfg(unix)]
fn set_extracted_permissions(path: &Path, file_attr: u64) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    if file_attr & 0o170000 != 0 {
        fs::set_permissions(
            path,
            fs::Permissions::from_mode(u32::try_from(file_attr & 0o777).unwrap_or(0o644)),
        )?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn set_extracted_permissions(_path: &Path, _file_attr: u64) -> std::io::Result<()> {
    Ok(())
}

pub(crate) fn checked_output_path(out_dir: &Path, rel: &Path) -> rars::Result<PathBuf> {
    let mut out_path = out_dir.to_path_buf();
    for component in rel.components() {
        let Component::Normal(part) = component else {
            return Err(Error::InvalidHeader("unsafe archive path"));
        };
        out_path.push(part);
        if fs::symlink_metadata(&out_path)
            .map(|metadata| metadata.file_type().is_symlink())
            .unwrap_or(false)
        {
            return Err(Error::InvalidHeader("unsafe archive path crosses symlink"));
        }
    }
    Ok(out_path)
}

pub(crate) fn print_ok_entry(entry: &ExtractedEntryMeta) {
    println!(
        "OK {}{}",
        display_archive_bytes(&entry.name),
        if entry.is_directory { "/" } else { "" }
    );
}

pub(crate) fn warn_rar50_redirections(archive: &DetectedArchive) {
    let DetectedArchive::Rar50Plus(archive) = archive else {
        return;
    };
    for file in archive.files().filter(|file| file.redirection.is_some()) {
        eprintln!("{}", redirection_warning(file.name_lossy()));
    }
}

pub(crate) fn redirection_warning(name: impl AsRef<str>) -> String {
    format!(
        "warning: RAR 5 redirection entry '{}' is not recreated; extraction treats only regular file payloads as writable output",
        display_archive_text(name.as_ref())
    )
}

fn display_archive_text(text: impl AsRef<str>) -> String {
    text.as_ref()
        .chars()
        .flat_map(char::escape_default)
        .collect()
}

fn display_archive_bytes(bytes: &[u8]) -> String {
    display_archive_text(String::from_utf8_lossy(bytes))
}

pub(crate) fn output_relative_path(name: &[u8]) -> CliResult<PathBuf> {
    if name.contains(&0) {
        return Err("unsafe archive path contains NUL byte".into());
    }
    let text = String::from_utf8(name.to_vec())
        .map_err(|_| CliError::general("archive entry name is not UTF-8"))?
        .replace('\\', "/");
    let bytes = text.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        return Err(format!("unsafe archive path: {text}").into());
    }
    let path = Path::new(&text);
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => out.push(part),
            Component::CurDir => {}
            _ => return Err(format!("unsafe archive path: {text}").into()),
        }
    }
    if out.as_os_str().is_empty() {
        return Err("empty archive path".into());
    }
    Ok(out)
}

fn create_output_file(path: &Path, overwrite: OverwritePolicy) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true);
    match overwrite {
        OverwritePolicy::Never => {
            options.create_new(true);
        }
        OverwritePolicy::Always => {
            options.create(true).truncate(true);
        }
    }
    set_no_follow(&mut options);
    options.open(path)
}

#[cfg(unix)]
fn set_no_follow(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    options.custom_flags(libc::O_NOFOLLOW);
}

#[cfg(not(unix))]
fn set_no_follow(_options: &mut OpenOptions) {
    // checked_output_path validates archive path components before open. The
    // standard library does not expose a cross-platform final-component
    // no-follow flag for this target family.
}

use crate::time::extracted_system_time;
use crate::{CliError, CliResult};
use rars::{
    Archive as DetectedArchive, ArchiveFamily, ArchiveVersion, AttrSource, Error,
    ExtractedEntryMeta,
};
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

/// Whether a backslash in an entry name separates path components.
///
/// RAR 1.5-4.x uses it as the wire separator, so there it does. RAR 5.0 uses
/// `/` for every host and a backslash is an ordinary character; see
/// [`rar50_entry_name`].
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Backslash {
    Separator,
    Literal,
}

impl Backslash {
    fn is_separator(self) -> bool {
        self == Self::Separator
    }
}

pub(crate) fn open_output_writer(
    out_dir: &Path,
    entry: &ExtractedEntryMeta,
    overwrite: OverwritePolicy,
    backslash: Backslash,
) -> rars::Result<(PathBuf, Box<dyn std::io::Write>)> {
    let resolve = |name: &[u8]| {
        relative_path(name, backslash.is_separator())
            .map_err(|_| Error::InvalidHeader("unsafe archive path"))
    };
    let mut out_path = checked_output_path(out_dir, &resolve(&entry.name)?)?;
    if entry.is_directory {
        fs::create_dir_all(&out_path)?;
        return Ok((out_path, Box::new(std::io::sink())));
    }
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let rel = resolve(&entry.name)?;
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

/// RAR 5.0 uses `/` as the separator for every host, so a backslash that
/// survives into a stored name is a literal character and not a delimiter.
/// Splitting on it would invent directory levels the archive never declared,
/// turning one entry into a tree.
///
/// Windows cannot hold a backslash in a filename, so it becomes `_` there
/// whatever the archive says. On Unix it is an ordinary character: the
/// reference keeps it verbatim for a Unix-host entry, and flattens it to `_`
/// for a Windows-host one, where the byte came from a platform that meant it
/// as a separator. Measured on RAR 7.12 and WinRAR 7.21's Rar.exe.
///
/// This is the opposite of RAR 1.5-4.x, where a backslash **is** the wire
/// separator, which is why [`output_relative_path`] still splits on it.
pub(crate) fn rar50_entry_name(name: &[u8], host_os: u64) -> Vec<u8> {
    const HOST5_UNIX: u64 = 1;
    if cfg!(unix) && host_os == HOST5_UNIX {
        return name.to_vec();
    }
    name.iter()
        .map(|&byte| if byte == b'\\' { b'_' } else { byte })
        .collect()
}

pub(crate) fn output_path_for_rar50_entry(
    out_dir: &Path,
    entry: &rars::rar50::ExtractedEntryMeta,
) -> rars::Result<PathBuf> {
    let rel = rar50_output_relative_path(&entry.name, entry.host_os)
        .map_err(|_| Error::InvalidHeader("unsafe archive path"))?;
    checked_output_path(out_dir, &rel)
}

/// [`output_relative_path`] for a RAR 5.0 entry, which does not treat a
/// backslash as a separator. See [`rar50_entry_name`].
pub(crate) fn rar50_output_relative_path(name: &[u8], host_os: u64) -> CliResult<PathBuf> {
    relative_path(&rar50_entry_name(name, host_os), false)
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
        if let Some(time) = extracted_system_time(
            output.family,
            output.meta.file_time,
            output.meta.mtime_refinement,
        ) {
            set_modified_time(&output.path, time)?;
        }
        set_extracted_permissions(
            &output.path,
            output.meta.file_attr,
            output.meta.attr_source,
            false,
        )?;
    }
    for output in outputs
        .iter()
        .filter(|output| output.restore_metadata && output.meta.is_directory)
    {
        set_extracted_permissions(
            &output.path,
            output.meta.file_attr,
            output.meta.attr_source,
            true,
        )?;
        if let Some(time) = extracted_system_time(
            output.family,
            output.meta.file_time,
            output.meta.mtime_refinement,
        ) {
            set_modified_time(&output.path, time)?;
        }
    }
    Ok(())
}

#[cfg(windows)]
fn set_modified_time(path: &Path, time: SystemTime) -> std::io::Result<()> {
    use std::os::windows::fs::OpenOptionsExt;

    const FILE_WRITE_ATTRIBUTES: u32 = 0x0100;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;

    OpenOptions::new()
        .access_mode(FILE_WRITE_ATTRIBUTES)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)?
        .set_modified(time)
}

#[cfg(not(windows))]
fn set_modified_time(path: &Path, time: SystemTime) -> std::io::Result<()> {
    File::open(path)?.set_modified(time)
}

#[cfg(unix)]
fn set_extracted_permissions(
    path: &Path,
    file_attr: u64,
    attr_source: AttrSource,
    is_directory: bool,
) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    const FILE_ATTRIBUTE_READONLY: u64 = 0x01;

    let mode = match attr_source {
        // A DOS attribute word says nothing about permissions except whether
        // the entry is read-only. Everything else is already right: the file
        // was created 0666 & ~umask and the directory 0777 & ~umask, which is
        // what the reference leaves behind, so only read-only needs acting on
        // and only on files.
        AttrSource::Dos => {
            (!is_directory && file_attr & FILE_ATTRIBUTE_READONLY != 0).then_some(0o444)
        }
        // A st_mode is applied verbatim, but only when it carries file-type
        // bits. Without them the value is not a mode, and stripping a file to
        // whatever the low bits happen to say is worse than leaving it.
        AttrSource::Unix if file_attr & 0o170000 != 0 => {
            Some(u32::try_from(file_attr & 0o777).unwrap_or(0o644))
        }
        AttrSource::Unix | AttrSource::Unknown => None,
        _ => None,
    };

    if let Some(mode) = mode {
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn set_extracted_permissions(
    _path: &Path,
    _file_attr: u64,
    _attr_source: AttrSource,
    _is_directory: bool,
) -> std::io::Result<()> {
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
    let mut out = String::new();
    for ch in text.as_ref().chars() {
        // Escape control characters (e.g. terminal escape sequences) so a
        // hostile archive name can't manipulate the terminal, but pass
        // printable Unicode such as Cyrillic or CJK through unchanged.
        if ch.is_control() {
            out.extend(ch.escape_default());
        } else {
            out.push(ch);
        }
    }
    out
}

fn display_archive_bytes(bytes: &[u8]) -> String {
    display_archive_text(String::from_utf8_lossy(bytes))
}

pub(crate) fn output_relative_path(name: &[u8]) -> CliResult<PathBuf> {
    relative_path(name, true)
}

fn relative_path(name: &[u8], backslash_is_separator: bool) -> CliResult<PathBuf> {
    if name.contains(&0) {
        return Err("unsafe archive path contains NUL byte".into());
    }
    let mut text = String::from_utf8(name.to_vec())
        .map_err(|_| CliError::general("archive entry name is not UTF-8"))?;
    if backslash_is_separator {
        text = text.replace('\\', "/");
    }
    let text = text;
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

#[cfg(test)]
mod tests {
    use super::{
        display_archive_text, output_relative_path, rar50_entry_name, rar50_output_relative_path,
        restore_output_metadata, ExtractedOutput,
    };
    use rars::{ArchiveFamily, ExtractedEntryMeta};
    use std::fs;

    fn scratch(name: &str) -> crate::scratch::Scratch {
        crate::scratch::case(&format!("rars-output-{name}"))
    }

    /// RAR 5.0 separates with `/` on every host, so a backslash in a name is a
    /// character. Splitting on it invents a directory the archive never
    /// declared. RAR 1.5-4.x is the opposite and must keep splitting.
    ///
    /// Matches RAR 7.12 on Unix: kept verbatim for a Unix-host entry, replaced
    /// with `_` for a Windows-host one.
    #[test]
    fn rar50_backslash_is_a_character_and_legacy_backslash_is_a_separator() {
        const UNIX: u64 = 1;
        const WINDOWS: u64 = 0;

        assert_eq!(
            rar50_entry_name(br"sub\nam.t", UNIX),
            br"sub\nam.t".to_vec()
        );
        assert_eq!(
            rar50_entry_name(br"sub\nam.t", WINDOWS),
            b"sub_nam.t".to_vec()
        );

        assert_eq!(
            rar50_output_relative_path(br"sub\nam.t", UNIX).unwrap(),
            std::path::Path::new(r"sub\nam.t")
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

    /// Keeping the backslash must not open a traversal: it stays inside one
    /// path component, so the `..` check never sees a parent directory.
    #[test]
    fn rar50_backslash_traversal_is_still_refused() {
        const UNIX: u64 = 1;
        assert!(rar50_output_relative_path(br"..\..\pwn", UNIX).is_ok());
        assert_eq!(
            rar50_output_relative_path(br"..\..\pwn", UNIX).unwrap(),
            std::path::Path::new(r"..\..\pwn")
        );
        assert!(rar50_output_relative_path(b"../../pwn", UNIX).is_err());
        assert!(output_relative_path(br"..\..\pwn").is_err());
    }

    #[test]
    fn display_archive_text_keeps_unicode_and_escapes_controls() {
        assert_eq!(
            display_archive_text("ваапап/WinRAR.exe"),
            "ваапап/WinRAR.exe"
        );
        assert_eq!(
            display_archive_text("x\u{1b}]0;evil\u{7}"),
            "x\\u{1b}]0;evil\\u{7}"
        );
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
                path: file,
                meta: ExtractedEntryMeta::new(b"payload.exe".to_vec(), 1_704_067_200, 0x20, false),
                family: ArchiveFamily::Rar50Plus,
                restore_metadata: true,
            },
            ExtractedOutput {
                name: b"nested".to_vec(),
                path: dir,
                meta: ExtractedEntryMeta::new(b"nested".to_vec(), 1_704_067_200, 0x10, true),
                family: ArchiveFamily::Rar50Plus,
                restore_metadata: true,
            },
        ];

        restore_output_metadata(&outputs).unwrap();
    }
}

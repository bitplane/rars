use crate::CliResult;
use rars::{Archive as DetectedArchive, AttrSource, Error, ExtractedEntryMeta};
use std::fs;
use std::path::{Path, PathBuf};

pub(crate) use rars::output_staging::{ExtractionStaging, OverwritePolicy};

pub(crate) struct ExtractedOutput {
    pub(crate) name: Vec<u8>,
    /// The member's stored path, which flattening or renaming may move it from.
    pub(crate) stored: PathBuf,
    pub(crate) path: PathBuf,
    pub(crate) meta: ExtractedEntryMeta,
    pub(crate) restore_metadata: bool,
}

#[cfg(test)]
const FSREDIR_UNIX_SYMLINK: u64 = 0x01;
#[cfg(test)]
const FSREDIR_HARDLINK: u64 = 0x04;
#[cfg(test)]
const FSREDIR_FILE_COPY: u64 = 0x05;

pub(crate) fn open_output_writer(
    out_dir: &Path,
    relative: &Path,
    directory: bool,
    overwrite: OverwritePolicy,
    renames: &mut rars::output_staging::RenameCounters,
) -> rars::Result<(PathBuf, Box<dyn std::io::Write + Send>)> {
    let mut out_path = checked_output_path(out_dir, relative)?;
    if directory {
        fs::create_dir_all(&out_path)?;
        return Ok((out_path, Box::new(std::io::sink())));
    }
    fs::create_dir_all(
        out_path
            .parent()
            .expect("validated output path has a parent"),
    )?;
    out_path = checked_output_path(out_dir, relative)?;
    let (out_path, file) = rars::output_staging::open_in_place(&out_path, overwrite, renames)?;
    Ok((out_path, Box::new(file)))
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
    rars::output_links::rar50_native_name(name, host_os == HOST5_UNIX)
}

/// [`output_relative_path`] for a RAR 5.0 entry, which does not treat a
/// backslash as a separator. See [`rar50_entry_name`].
pub(crate) fn rar50_output_relative_path(name: &[u8], host_os: u64) -> CliResult<PathBuf> {
    relative_path(&rar50_entry_name(name, host_os), false)
}

pub(crate) use rars::output_links::{create_link_output, link_source_path};

pub(crate) fn restore_output_metadata(outputs: &[ExtractedOutput]) -> std::io::Result<()> {
    let restored: Vec<_> = outputs
        .iter()
        .filter(|output| output.restore_metadata)
        .collect();
    let mut times = rars::output_times::OutputTimes::new();
    for output in &restored {
        times.opened(output.path.clone(), &output.meta);
    }
    times.finish();
    times.restore()?;
    let (mut directories, files): (Vec<_>, Vec<_>) = restored
        .into_iter()
        .partition(|output| output.meta.is_directory);
    for output in files {
        set_extracted_permissions(
            &output.path,
            output.meta.file_attr,
            output.meta.attr_source,
            false,
        )?;
    }
    // Finish descendants before a parent's mode can deny access to them.
    directories.sort_by_cached_key(|output| std::cmp::Reverse(output.path.components().count()));
    for output in directories {
        set_extracted_permissions(
            &output.path,
            output.meta.file_attr,
            output.meta.attr_source,
            true,
        )?;
    }
    Ok(())
}

/// The modified time and mode a regular file can take before it is
/// published, or `None` when they wait for the end: a mode that denies its
/// owner reading would stop a later member copying from it.
pub(crate) fn early_file_metadata(output: &ExtractedOutput) -> Option<EarlyMetadata> {
    output
        .restore_metadata
        .then(|| early_metadata(&output.meta))
        .flatten()
}

/// A file's modified time and mode, set before it is published.
pub(crate) type EarlyMetadata = (Option<std::time::SystemTime>, Option<u32>);

fn early_metadata(meta: &ExtractedEntryMeta) -> Option<EarlyMetadata> {
    let mode = extracted_mode(meta.file_attr, meta.attr_source, false);
    if mode.is_some_and(|mode| mode & 0o400 == 0) {
        return None;
    }
    let modified = meta
        .modified
        .and_then(|time| std::time::SystemTime::try_from(time).ok());
    Some((modified, mode))
}

/// The permission bits a member's file is created with: its own, when they
/// can be set before it is published, else 0666.
pub(crate) fn create_mode(meta: &ExtractedEntryMeta) -> u32 {
    create_mode_for(early_metadata(meta))
}

fn create_mode_for(early: Option<EarlyMetadata>) -> u32 {
    early.and_then(|(_, mode)| mode).unwrap_or(0o666)
}

/// Whether `file` has exactly the permission bits `mode`.
#[cfg(unix)]
pub(crate) fn has_mode(file: &fs::File, mode: u32) -> bool {
    use std::os::unix::fs::PermissionsExt;
    file.metadata()
        .is_ok_and(|metadata| metadata.permissions().mode() & 0o7777 == mode)
}

#[cfg(not(unix))]
pub(crate) fn has_mode(_file: &fs::File, _mode: u32) -> bool {
    false
}

/// Whether creating a file in one directory with given permission bits
/// gives it exactly those bits, for each set of bits a file there was created
/// with: the umask or a default ACL may clear some. Learnt from the first file
/// created with each, so the others need no change when they are kept. The
/// CLI never changes its umask.
#[derive(Clone)]
pub(crate) struct CreatedModes {
    #[cfg(unix)]
    known: std::sync::Arc<[std::sync::atomic::AtomicU8]>,
}

impl Default for CreatedModes {
    fn default() -> Self {
        Self {
            #[cfg(unix)]
            known: (0..=0o7777).map(|_| Default::default()).collect(),
        }
    }
}

impl CreatedModes {
    // Not known yet is 0, as each starts.
    #[cfg(unix)]
    const KEPT: u8 = 1;
    #[cfg(unix)]
    const CHANGED: u8 = 2;

    /// Whether `file`, created here with the permission bits `mode` and not
    /// changed since, has them.
    #[cfg(unix)]
    fn kept(&self, file: &fs::File, mode: u32) -> bool {
        use std::os::unix::fs::PermissionsExt;
        use std::sync::atomic::Ordering;
        let Some(known) = self.known.get(mode as usize) else {
            return false;
        };
        match known.load(Ordering::Relaxed) {
            Self::KEPT => true,
            Self::CHANGED => false,
            _ => {
                let Ok(metadata) = file.metadata() else {
                    return false;
                };
                let kept = metadata.permissions().mode() & 0o7777 == mode;
                known.store(
                    if kept { Self::KEPT } else { Self::CHANGED },
                    Ordering::Relaxed,
                );
                kept
            }
        }
    }

    #[cfg(not(unix))]
    fn kept(&self, _file: &fs::File, _mode: u32) -> bool {
        false
    }
}

/// A staged file, created and finished on whichever thread writes it. It is
/// created on its first write or flush, or as it is dropped, so the thread
/// that opens it pays for no system call. As it is closed it takes its early
/// metadata through its own descriptor; `set` records whether it did, and
/// publication sets anything it did not.
pub(crate) struct StagedFile {
    file: Result<fs::File, Option<(rars::output_tree::FileDir, std::ffi::OsString)>>,
    early: Option<EarlyMetadata>,
    set: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// The permission bits it is created with: its member's, when known.
    create_mode: u32,
    created_modes: CreatedModes,
}

impl StagedFile {
    /// A file created now as `name` in `dir`.
    pub(crate) fn new(
        dir: rars::output_tree::FileDir,
        name: std::ffi::OsString,
        meta: &ExtractedEntryMeta,
        created_modes: CreatedModes,
    ) -> std::io::Result<(Self, std::sync::Arc<std::sync::atomic::AtomicBool>)> {
        let (mut staged, set) = Self::deferred(dir, name, meta, created_modes);
        staged.file()?;
        Ok((staged, set))
    }

    /// A file to create as `name` in `dir` once it is first used.
    pub(crate) fn deferred(
        dir: rars::output_tree::FileDir,
        name: std::ffi::OsString,
        meta: &ExtractedEntryMeta,
        created_modes: CreatedModes,
    ) -> (Self, std::sync::Arc<std::sync::atomic::AtomicBool>) {
        let set = std::sync::Arc::default();
        let early = early_metadata(meta);
        let staged = Self {
            file: Err(Some((dir, name))),
            early,
            set: std::sync::Arc::clone(&set),
            create_mode: create_mode_for(early),
            created_modes,
        };
        (staged, set)
    }

    fn file(&mut self) -> std::io::Result<&mut fs::File> {
        if let Err(pending) = &mut self.file {
            let (dir, name) = pending
                .take()
                .ok_or_else(|| std::io::Error::other("the staged file could not be created"))?;
            self.file = Ok(dir.create_file(&name, self.create_mode)?);
        }
        match &mut self.file {
            Ok(file) => Ok(file),
            Err(_) => unreachable!("created above"),
        }
    }
}

impl std::io::Write for StagedFile {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.file()?.write(buf)
    }

    fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        self.file()?.write_all(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file()?.flush()
    }
}

impl Drop for StagedFile {
    fn drop(&mut self) {
        let early = self.early;
        let create_mode = self.create_mode;
        let created_modes = self.created_modes.clone();
        // An empty member nothing flushed is still a file.
        let Ok(file) = self.file() else {
            return;
        };
        let Some((modified, mode)) = early else {
            return;
        };
        let set = (|| {
            if let Some(modified) = modified {
                file.set_modified(modified)?;
            }
            // Created with its mode, it keeps it unless the umask cleared some.
            let kept = |mode| mode == create_mode && created_modes.kept(file, mode);
            if let Some(mode) = mode.filter(|&mode| !kept(mode)) {
                set_file_mode(file, mode)?;
            }
            std::io::Result::Ok(())
        })();
        self.set
            .store(set.is_ok(), std::sync::atomic::Ordering::Release);
    }
}

#[cfg(unix)]
pub(crate) fn set_file_mode(file: &fs::File, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
pub(crate) fn set_file_mode(_file: &fs::File, _mode: u32) -> std::io::Result<()> {
    Err(std::io::ErrorKind::Unsupported.into())
}

#[cfg(unix)]
fn set_extracted_permissions(
    path: &Path,
    file_attr: u64,
    attr_source: AttrSource,
    is_directory: bool,
) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    if let Some(mode) = extracted_mode(file_attr, attr_source, is_directory) {
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    Ok(())
}

#[cfg(unix)]
fn extracted_mode(file_attr: u64, attr_source: AttrSource, is_directory: bool) -> Option<u32> {
    const FILE_ATTRIBUTE_READONLY: u64 = 0x01;

    match attr_source {
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
        AttrSource::Unix if file_attr & 0o170000 != 0 => Some((file_attr & 0o777) as u32),
        // Missing type bits and unknown (including future) hosts leave modes unchanged.
        _ => None,
    }
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

#[cfg(not(unix))]
fn extracted_mode(_file_attr: u64, _attr_source: AttrSource, _is_directory: bool) -> Option<u32> {
    None
}

pub(crate) fn checked_output_path(out_dir: &Path, rel: &Path) -> rars::Result<PathBuf> {
    rars::filename::checked_output_path(out_dir, rel).map_err(path_error)
}

/// Reports an unsafe output path as a bad header, as every extraction refusal is.
fn path_error(error: Error) -> Error {
    match error {
        Error::UnsafePath(message) => Error::InvalidHeader(message),
        other => other,
    }
}

/// Reports an unsafe output path as [`checked_output_path`] does, naming the
/// member. Other errors pass through unchanged.
pub(crate) fn refused_path(error: Error, name: &[u8]) -> Error {
    match error {
        Error::UnsafePath(_) => rars::output_staging::refused_output(path_error(error), name),
        other => other,
    }
}

pub(crate) fn print_ok_entry(entry: &ExtractedEntryMeta) {
    print_ok_name(&entry.name, entry.is_directory);
}

pub(crate) fn print_ok_name(name: &[u8], is_directory: bool) {
    println!(
        "OK {}{}",
        display_archive_bytes(name),
        if is_directory { "/" } else { "" }
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

pub(crate) fn incomplete_member_warning(volume: &Path, member: &rars::IncompleteMember) -> String {
    let missing = match member.missing {
        rars::MissingPart::Start => "its start is in a missing earlier volume",
        rars::MissingPart::End => "its end is in a missing later volume",
        _ => "its start and end are in missing volumes",
    };
    format!(
        "warning: {}: skipped split member '{}': {missing}",
        volume.display(),
        display_archive_bytes(&member.name)
    )
}

/// A member `test` or `x` failed on and went past. `hint` follows the error.
pub(crate) fn damaged_member_warning(
    path: &Path,
    name: &[u8],
    error: &rars::Error,
    hint: &str,
) -> String {
    match error.entry_context() {
        Some(_) => format!("warning: {}: {error}{hint}", path.display()),
        None => format!(
            "warning: {}: '{}': {error}{hint}",
            path.display(),
            display_archive_bytes(name)
        ),
    }
}

/// A damaged member `x --keep-broken` kept, with what was read of it.
pub(crate) fn kept_broken_warning(path: &Path, name: &[u8], error: &rars::Error) -> String {
    format!(
        "warning: {}: '{}': kept broken: {}",
        path.display(),
        display_archive_bytes(name),
        error.root_cause()
    )
}

pub(crate) fn truncation_warning(path: &Path, truncation: &rars::Truncation) -> String {
    format!("warning: {}: archive is {truncation}", path.display())
}

/// Warns that an archive ends early, about each malformed block its reader
/// passed over, and about each damaged header a salvaging read went past.
pub(crate) fn warn_archive_structure(path: &Path, archive: &DetectedArchive) {
    for damage in archive.header_damage() {
        eprintln!("warning: {}: {damage}", path.display());
    }
    for skipped in archive.skipped_blocks() {
        eprintln!("warning: {}: {skipped}", path.display());
    }
    if let Some(truncation) = archive.truncation() {
        eprintln!("{}", truncation_warning(path, truncation));
    }
}

pub(crate) fn skipped_link_warning(name: &[u8], target: &[u8]) -> String {
    format!(
        "warning: skipping link '{}' -> '{}': it would point outside the output directory",
        display_archive_bytes(name),
        display_archive_bytes(target)
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
    match rars::filename::relative_path(name, backslash_is_separator) {
        Ok(path) => Ok(path),
        Err(Error::UnsafePath("unsafe archive path contains NUL byte")) => {
            Err("unsafe archive path contains NUL byte".into())
        }
        Err(Error::InvalidHeader("empty archive path")) => Err("empty archive path".into()),
        Err(Error::UnsafePath(_)) => {
            // Preserve the CLI's diagnostic path spelling on the error path.
            let bytes: Vec<_> = name
                .iter()
                .map(|&byte| {
                    if backslash_is_separator && byte == b'\\' {
                        b'/'
                    } else {
                        byte
                    }
                })
                .collect();
            let text = rars::filename::native_string(&bytes)?;
            Err(format!("unsafe archive path: {}", Path::new(&text).display()).into())
        }
        Err(error) => Err(error.into()),
    }
}

pub(crate) use rars::output_staging::publish_verified_output;

#[cfg(test)]
mod tests {
    use super::{
        display_archive_text, output_relative_path, rar50_entry_name, rar50_output_relative_path,
        restore_output_metadata, ExtractedOutput,
    };
    use rars::{ArchiveFamily, ExtractedEntryMeta};
    use std::collections::HashMap;
    use std::fs;

    fn scratch(name: &str) -> crate::scratch::Scratch {
        crate::scratch::case(&format!("rars-output-{name}"))
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
        let mut tree = rars::output_tree::OutputTree::open(&root).unwrap().unwrap();
        let dir = tree.file_dir(std::path::Path::new("files")).unwrap();
        let created_modes = super::CreatedModes::default();
        let modes = [
            0o600, 0o644, 0o777, 0o755, 0o664, 0o600, 0o777, 0o644, 0o400,
        ];
        for (index, mode) in modes.into_iter().enumerate() {
            let name = std::ffi::OsString::from(index.to_string());
            let meta =
                ExtractedEntryMeta::new(b"member".to_vec(), None, 0o100000 | mode as u64, false)
                    .with_attr_source(rars::AttrSource::Unix);
            let (mut file, set) = if index % 2 == 0 {
                super::StagedFile::deferred(dir.clone(), name, &meta, created_modes.clone())
            } else {
                super::StagedFile::new(dir.clone(), name, &meta, created_modes.clone()).unwrap()
            };
            file.write_all(b"data").unwrap();
            drop(file);
            assert!(set.load(std::sync::atomic::Ordering::Acquire), "{mode:o}");
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
        use super::*;
        let root = scratch("staging-alias");
        let mut state = crate::ExtractOutputState::new(
            &root,
            OverwritePolicy::Always,
            false,
            false,
            ArchiveFamily::Rar50Plus,
        );
        state
            .open_entry(&rars::ExtractedEntryMeta::new(
                b"ordinary".to_vec(),
                None,
                0,
                false,
            ))
            .unwrap();
        let storage = state.publisher.staging().unwrap().root.clone();
        let alias = storage
            .file_name()
            .unwrap()
            .to_string_lossy()
            .to_uppercase();
        // On a case-sensitive host this distinct name is a legitimate output.
        let aliases_storage = root.join(&alias).exists();
        let name = format!("{alias}/payload").into_bytes();
        let result = state.open_entry(&rars::ExtractedEntryMeta::new(name, None, 0, false));
        if aliases_storage {
            assert!(matches!(
                result,
                Err(Error::InvalidHeader(
                    "archive path conflicts with extraction storage"
                ))
            ));
            // The earlier member was published before the alias was refused,
            // leaving nothing staged, only perhaps the empty directory files
            // stage in.
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
        use super::*;
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
            assert!(rars::filename::relative_path(&meta.name, true).is_err());
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
        use super::*;
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
        use super::*;
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
        use super::*;
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
        assert!(create_rar50_redirection(
            &dir,
            &meta,
            &redirection,
            OverwritePolicy::Never,
            &created
        )
        .is_err());
        assert!(destination.is_dir());
        fs::write(destination.join("keep"), b"keep").unwrap();
        assert!(create_rar50_redirection(
            &dir,
            &meta,
            &redirection,
            OverwritePolicy::Always,
            &created
        )
        .is_err());
        assert_eq!(fs::read(destination.join("keep")).unwrap(), b"keep");
        fs::remove_file(destination.join("keep")).unwrap();
        create_rar50_redirection(&dir, &meta, &redirection, OverwritePolicy::Always, &created)
            .unwrap();
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
        use super::*;
        use std::io::Write;
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
                    let mut state = crate::ExtractOutputState::new(
                        &root,
                        overwrite,
                        false,
                        false,
                        ArchiveFamily::Rar50Plus,
                    );
                    let (mut meta, mut redirection) = redirection_fixture();
                    meta.name = b"source".to_vec();
                    state
                        .open_entry(&rars::rar50_meta(&meta))
                        .unwrap()
                        .write_all(b"payload")
                        .unwrap();
                    meta.name = b"destination".to_vec();
                    redirection.target_name = b"source".to_vec();
                    redirection.redirection_type = kind;
                    let staged = state
                        .create_link(&rars::rar50_meta(&meta), test_link(&redirection).unwrap());
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
        use super::*;
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
        use super::*;
        let dir = scratch("metadata-errors");
        for directory in [false, true] {
            for timestamp in [
                None,
                Some(rars::Timestamp::from_unix_seconds(1_704_067_200)),
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
                    .with_attr_source(AttrSource::Unix),
                    restore_metadata: false,
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

    #[cfg(unix)]
    #[test]
    fn permissions_respect_attribute_source_and_type_bits() {
        use super::*;
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("permission-policy");
        for (source, attr, directory, expected) in [
            (AttrSource::Dos, 0, false, 0o640),
            (AttrSource::Dos, 1, false, 0o444),
            (AttrSource::Dos, 1, true, 0o640),
            (AttrSource::Unix, 0o777, false, 0o640),
            (AttrSource::Unix, 0o100754, false, 0o754),
            (AttrSource::Unix, u64::MAX, false, 0o777),
            (AttrSource::Unknown, u64::MAX, false, 0o640),
        ] {
            let path = dir.join("entry");
            if path.exists() {
                if path.is_dir() {
                    fs::remove_dir(&path).unwrap();
                } else {
                    fs::remove_file(&path).unwrap();
                }
            }
            if directory {
                fs::create_dir(&path).unwrap();
            } else {
                fs::write(&path, b"payload").unwrap();
            }
            fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
            set_extracted_permissions(&path, attr, source, directory).unwrap();
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                expected
            );
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        }
    }

    // Keep raw RAR5 fixtures to exercise the same filename and filesystem cases.
    fn test_link(link: &rars::rar50::FileRedirection) -> rars::Result<rars::ExtractedLink<'_>> {
        use rars::ExtractedLink::*;
        let target = &link.target_name;
        Ok(match link.redirection_type {
            1 | 2 => Symlink {
                target,
                directory: link.flags & 1 != 0,
            },
            3 => Junction { target },
            4 => HardLink { target },
            5 => FileCopy { target },
            _ => return Err(rars::Error::InvalidHeader("unsupported archive link type")),
        })
    }
    fn create_rar50_redirection(
        out: &std::path::Path,
        meta: &rars::rar50::ExtractedEntryMeta,
        link: &rars::rar50::FileRedirection,
        overwrite: super::OverwritePolicy,
        created: &std::collections::HashMap<std::path::PathBuf, std::path::PathBuf>,
    ) -> rars::Result<(std::path::PathBuf, bool)> {
        let relative = super::rar50_output_relative_path(&meta.name, meta.host_os)
            .map_err(|_| rars::Error::InvalidHeader("unsafe archive path"))?;
        let target = super::rar50_output_relative_path(&link.target_name, meta.host_os)
            .map_err(|_| rars::Error::InvalidHeader("unsafe archive redirection target"))?;
        super::create_link_output(
            out,
            &relative,
            &target,
            test_link(link)?,
            overwrite,
            created,
            &mut Default::default(),
        )
    }
    fn output_path_for_rar50_entry(
        out: &std::path::Path,
        meta: &rars::rar50::ExtractedEntryMeta,
    ) -> rars::Result<std::path::PathBuf> {
        let relative = super::rar50_output_relative_path(&meta.name, meta.host_os)
            .map_err(|_| rars::Error::InvalidHeader("unsafe archive path"))?;
        super::checked_output_path(out, &relative)
    }
    fn open_test_writer(
        out: &std::path::Path,
        meta: &rars::ExtractedEntryMeta,
        overwrite: super::OverwritePolicy,
    ) -> rars::Result<(std::path::PathBuf, Box<dyn std::io::Write>)> {
        let relative = rars::filename::relative_path(&meta.name, true)?;
        super::open_output_writer(
            out,
            &relative,
            meta.is_directory,
            overwrite,
            &mut Default::default(),
        )
        .map(|(path, writer)| (path, writer as Box<dyn std::io::Write>))
    }

    fn redirection_fixture() -> (
        rars::rar50::ExtractedEntryMeta,
        rars::rar50::FileRedirection,
    ) {
        let archive = rars::rar50::Archive::parse(include_bytes!(
            "../../rars/tests/fixtures/rar50/wild/hardlink.rar"
        ))
        .unwrap();
        let file = archive
            .files()
            .find(|file| file.redirection.is_some())
            .unwrap();
        (file.metadata(), file.redirection.clone().unwrap())
    }

    #[cfg(unix)]
    #[test]
    fn rar50_mapped_names_are_resolved_once_for_files_and_redirections() {
        use super::*;
        use std::ffi::OsStr;
        use std::io::Write;
        use std::os::unix::ffi::OsStrExt;
        for kind in [FSREDIR_HARDLINK, FSREDIR_FILE_COPY, FSREDIR_UNIX_SYMLINK] {
            let dir = scratch("mapped-redirections");
            let mut state = crate::ExtractOutputState::new(
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
            meta.name = rars::filename::encode_rar50(literal).into_owned();
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
                Err(error) if error.raw_os_error() == Some(libc::EILSEQ) => {
                    "source-\u{e0ff}".as_bytes()
                }
                Err(error) => panic!("literal filename probe failed unexpectedly: {error}"),
            };
            meta.name = rars::filename::encode_rar50(native).into_owned();
            state
                .open_entry(&rars::rar50_meta(&meta))
                .unwrap()
                .write_all(b"payload")
                .unwrap();
            assert_eq!(state.last_opened().unwrap().name, meta.name);
            redirection.target_name = meta.name.clone();
            redirection.redirection_type = kind;
            let link = if crate::scratch::supports_raw_byte_names(&dir) {
                b"link-\xff".as_slice()
            } else {
                b"link-unicode".as_slice()
            };
            meta.name = rars::filename::encode_rar50(link).into_owned();
            state
                .create_link(&rars::rar50_meta(&meta), test_link(&redirection).unwrap())
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
        use super::*;
        use std::io::Write;

        for host_os in [0, 1] {
            for kind in [FSREDIR_HARDLINK, FSREDIR_FILE_COPY, FSREDIR_UNIX_SYMLINK] {
                if kind == FSREDIR_UNIX_SYMLINK && !cfg!(unix) {
                    continue;
                }
                let dir = scratch("rar50-redirection-paths");
                let mut state = crate::ExtractOutputState::new(
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
                    state
                        .open_entry(&rars::rar50_meta(&meta))
                        .unwrap()
                        .write_all(data)
                        .unwrap();
                }

                meta.name = br"links\item".to_vec();
                redirection.redirection_type = kind;
                redirection.target_name = br"sub\file".to_vec();
                state
                    .create_link(&rars::rar50_meta(&meta), test_link(&redirection).unwrap())
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
                        .create_link(&rars::rar50_meta(&meta), test_link(&redirection).unwrap())
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
        use super::*;
        use std::io::Write;

        for host_os in [0, 1] {
            let dir = scratch("rar50-redirection-collision");
            let mut state = crate::ExtractOutputState::new(
                &dir,
                OverwritePolicy::Always,
                false,
                false,
                ArchiveFamily::Rar50Plus,
            );
            let (mut meta, mut redirection) = redirection_fixture();
            meta.host_os = host_os;
            meta.name = br"same\name".to_vec();
            state
                .open_entry(&rars::rar50_meta(&meta))
                .unwrap()
                .write_all(b"keep me")
                .unwrap();
            let name = if cfg!(unix) && host_os == 1 {
                r"same\name"
            } else {
                "same_name"
            };
            meta.name = format!("./{name}").into_bytes();
            redirection.redirection_type = FSREDIR_FILE_COPY;
            redirection.target_name = br"same\name".to_vec();
            assert!(matches!(
                state.create_link(&rars::rar50_meta(&meta), test_link(&redirection).unwrap()),
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
        use super::*;
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
        use super::*;
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
        assert!(create_rar50_redirection(
            &dir,
            &meta,
            &redirection,
            OverwritePolicy::Never,
            &created,
        )
        .is_err());
        assert_eq!(fs::read(&destination).unwrap(), b"old");
        create_rar50_redirection(&dir, &meta, &redirection, OverwritePolicy::Always, &created)
            .unwrap();
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
                stored: std::path::PathBuf::new(),
                path: file,
                meta: ExtractedEntryMeta::new(
                    b"payload.exe".to_vec(),
                    Some(rars::Timestamp::from_unix_seconds(1_704_067_200)),
                    0x20,
                    false,
                ),
                restore_metadata: true,
            },
            ExtractedOutput {
                name: b"nested".to_vec(),
                stored: std::path::PathBuf::new(),
                path: dir,
                meta: ExtractedEntryMeta::new(
                    b"nested".to_vec(),
                    Some(rars::Timestamp::from_unix_seconds(1_704_067_200)),
                    0x10,
                    true,
                ),
                restore_metadata: true,
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
                        Some(rars::Timestamp::from_unix_seconds(
                            1_704_067_200 + index as i64,
                        )),
                        0o040000,
                        true,
                    )
                    .with_attr_source(rars::AttrSource::Unix),
                    restore_metadata: true,
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
}

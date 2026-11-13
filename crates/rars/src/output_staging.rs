//! Verified outputs publish as new inodes, so a hard link or FIFO at the destination is never written through.

use crate::atomic64::AtomicU64;
use crate::Error;
use std::cell::OnceCell;
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;

/// Private, same-filesystem storage for a verified extraction's pending outputs.
pub struct ExtractionStaging {
    pub root: PathBuf,
    /// Resolve once, on the first alias check. Publication-only staging
    /// never needs the resolved root.
    identity: OnceCell<PathBuf>,
}

impl ExtractionStaging {
    pub fn new(out_dir: &Path) -> std::io::Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        fs::create_dir_all(out_dir)?;
        for _ in 0..128 {
            let root = out_dir.join(format!(
                ".rars-extract-{}-{:016x}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let mut builder = fs::DirBuilder::new();
            builder.recursive(false);
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            match builder.create(&root) {
                Ok(()) => {
                    return Ok(Self {
                        root,
                        identity: OnceCell::new(),
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "could not create private extraction storage",
        ))
    }

    /// Refuses a destination that resolves into the storage. Returns the
    /// destination's resolved path when it exists, so callers need not
    /// resolve it again.
    pub fn reject_alias(&self, destination: &Path) -> crate::Result<Option<PathBuf>> {
        let storage = match self.identity.get() {
            Some(storage) => storage,
            None => {
                let storage = fs::canonicalize(&self.root)?;
                self.identity.get_or_init(|| storage)
            }
        };
        let mut ancestor = Some(destination);
        while let Some(path) = ancestor {
            if missing(path) {
                ancestor = path.parent();
                continue;
            }
            match fs::canonicalize(path) {
                Ok(identity) => {
                    if identity.starts_with(storage) {
                        return Err(Error::InvalidHeader(
                            "archive path conflicts with extraction storage",
                        ));
                    }
                    return Ok((path == destination).then_some(identity));
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                    ) =>
                {
                    ancestor = path.parent();
                }
                Err(error) => return Err(error.into()),
            }
        }
        Ok(None)
    }
}

/// Whether `path` certainly does not exist, so resolving it can only fail:
/// one lstat instead of resolving every component to learn the same. Other
/// errors are left for `canonicalize` to report. On Windows a failed resolve
/// is already a single failed open, so the question would only add one.
#[cfg(unix)]
fn missing(path: &Path) -> bool {
    fs::symlink_metadata(path).is_err_and(|error| {
        matches!(
            error.kind(),
            std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
        )
    })
}

#[cfg(not(unix))]
fn missing(_path: &Path) -> bool {
    false
}

impl Drop for ExtractionStaging {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// The archive name of the entry an extraction error is attributed to.
pub fn failed_entry_name(error: &Error) -> Option<&[u8]> {
    match error {
        Error::AtEntry { name, .. } => Some(name),
        Error::AtArchiveOffset { source, .. } | Error::InVolume { source, .. } => {
            failed_entry_name(source)
        }
        _ => None,
    }
}

/// Names the member whose destination was refused, so every front end reports it alike.
pub fn refused_output(error: Error, name: &[u8]) -> Error {
    if error.entry_context().is_some() {
        error
    } else {
        error.at_entry(name.to_vec(), "extracting")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverwritePolicy {
    Never,
    Always,
    /// Writes beside what is there as `name(N).ext`, keeping both.
    Rename,
}

/// `path` with `(n)` before its last dot, or at its end when it has none.
fn numbered(path: &Path, n: u32) -> crate::Result<PathBuf> {
    let name = crate::filename::native_bytes(path.file_name().expect("output path has a name"))?;
    let split = name
        .iter()
        .rposition(|&byte| byte == b'.')
        .unwrap_or(name.len());
    let mut renamed = name[..split].to_vec();
    renamed.extend_from_slice(format!("({n})").as_bytes());
    renamed.extend_from_slice(&name[split..]);
    Ok(path.with_file_name(crate::filename::native_string(&renamed)?))
}

/// The next number `Rename` tries for each destination, so an archive repeating one name costs linear time.
#[derive(Default)]
pub struct RenameCounters {
    next: HashMap<PathBuf, u32>,
}

impl RenameCounters {
    /// Tries `path`, then `name(N).ext` upwards, until `create` makes one that did not exist.
    pub(crate) fn claim<T>(
        &mut self,
        path: &Path,
        mut create: impl FnMut(&Path) -> std::io::Result<T>,
    ) -> crate::Result<(PathBuf, T)> {
        let first = self.next.get(path).copied().unwrap_or(0);
        for n in first..=u32::MAX {
            let candidate = if n == 0 {
                path.to_path_buf()
            } else {
                numbered(path, n)?
            };
            match create(&candidate) {
                Ok(value) => {
                    self.next.insert(path.to_path_buf(), n.saturating_add(1));
                    return Ok((candidate, value));
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err(std::io::Error::from(std::io::ErrorKind::AlreadyExists).into())
    }
}

/// Where a member goes in flat mode: straight under the output directory.
pub fn flat_relative(relative: &Path) -> PathBuf {
    PathBuf::from(relative.file_name().expect("output path has a name"))
}

/// The first member to take each flattened name, so a refused repeat names both.
#[derive(Default)]
pub struct FlatNames {
    first: HashMap<PathBuf, Vec<u8>>,
}

impl FlatNames {
    pub fn claim(
        &mut self,
        relative: &Path,
        member: &[u8],
        overwrite: OverwritePolicy,
    ) -> crate::Result<()> {
        match self.first.get(relative) {
            Some(first) if overwrite == OverwritePolicy::Never => Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!(
                    "'{}' and '{}' both extract to '{}'",
                    String::from_utf8_lossy(first),
                    String::from_utf8_lossy(member),
                    relative.display()
                ),
            )
            .into()),
            Some(_) => Ok(()),
            None => {
                self.first.insert(relative.to_path_buf(), member.to_vec());
                Ok(())
            }
        }
    }
}

#[cfg(unix)]
pub fn create_symlink(target: &Path, link: &Path, _directory: bool) -> std::io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

#[cfg(windows)]
pub fn create_symlink(target: &Path, link: &Path, directory: bool) -> std::io::Result<()> {
    if directory {
        std::os::windows::fs::symlink_dir(target, link)
    } else {
        std::os::windows::fs::symlink_file(target, link)
    }
}

#[cfg(not(any(unix, windows)))]
pub fn create_symlink(_target: &Path, _link: &Path, _directory: bool) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "symbolic links are not supported on this platform",
    ))
}

fn copy_verified_output(source: &Path, destination: &Path) -> std::io::Result<()> {
    let file_type = fs::symlink_metadata(source)?.file_type();
    if file_type.is_symlink() {
        #[cfg(windows)]
        let directory = {
            use std::os::windows::fs::FileTypeExt;
            file_type.is_symlink_dir()
        };
        #[cfg(not(windows))]
        let directory = false;
        return create_symlink(&fs::read_link(source)?, destination, directory);
    }
    // create_new refuses any existing final component, symlinks included.
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)?;
    std::io::copy(&mut File::open(source)?, &mut output)?;
    Ok(())
}

fn publish_no_replace(
    source: &Path,
    destination: &Path,
    link: impl FnOnce(&Path, &Path) -> std::io::Result<()>,
) -> std::io::Result<()> {
    // Directory symlinks cannot be published using Windows hard-link APIs.
    if fs::symlink_metadata(source)?.file_type().is_symlink() {
        return copy_verified_output(source, destination);
    }
    match link(source, destination) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Err(error),
        // Includes filesystems without hard links and nested destination mounts.
        // create_new retains the no-overwrite guarantee in this fallback.
        Err(_) => copy_verified_output(source, destination),
    }
}

/// Opens the destination itself, refusing a link or special file that writing would reach through.
pub fn open_in_place(
    path: &Path,
    overwrite: OverwritePolicy,
    renames: &mut RenameCounters,
) -> crate::Result<(PathBuf, File)> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    match overwrite {
        OverwritePolicy::Never => return Ok((path.to_path_buf(), options.open(path)?)),
        OverwritePolicy::Rename => return renames.claim(path, |path| options.open(path)),
        OverwritePolicy::Always => {}
    }
    Ok((path.to_path_buf(), replace_in_place(path)?))
}

fn replace_in_place(path: &Path) -> std::io::Result<File> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        // O_NONBLOCK fails a FIFO with no reader instead of waiting for one.
        let file = options
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .map_err(|error| match error.raw_os_error() {
                Some(libc::ELOOP | libc::ENXIO) => refused_in_place(),
                _ => error,
            })?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.nlink() > 1 {
            return Err(refused_in_place());
        }
        file.set_len(0)?;
        Ok(file)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        let file = options
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        if !file.metadata()?.is_file() {
            return Err(refused_in_place());
        }
        file.set_len(0)?;
        Ok(file)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let file = options.open(path)?;
        file.set_len(0)?;
        Ok(file)
    }
}

fn refused_in_place() -> std::io::Error {
    std::io::Error::other("refusing to write in place through a link or special file")
}

/// A new inode, so whatever `destination` held is replaced rather than written through.
pub fn publish_verified_output(
    source: &Path,
    destination: &Path,
    overwrite: OverwritePolicy,
    hardlink_target: Option<&Path>,
    renames: &mut RenameCounters,
) -> crate::Result<PathBuf> {
    publish_verified_output_with_rename(
        source,
        destination,
        overwrite,
        hardlink_target,
        renames,
        |from, to| fs::rename(from, to),
    )
}

fn publish_verified_output_with_rename(
    source: &Path,
    destination: &Path,
    overwrite: OverwritePolicy,
    hardlink_target: Option<&Path>,
    renames: &mut RenameCounters,
    mut rename: impl FnMut(&Path, &Path) -> std::io::Result<()>,
) -> crate::Result<PathBuf> {
    let link = |to: &Path| {
        publish_no_replace(source, to, |from, to| {
            fs::hard_link(hardlink_target.unwrap_or(from), to)
        })
    };
    let published = match overwrite {
        OverwritePolicy::Never => {
            link(destination)?;
            destination.to_path_buf()
        }
        OverwritePolicy::Rename => renames.claim(destination, link)?.0,
        OverwritePolicy::Always => match rename(source, destination) {
            Ok(()) => return Ok(destination.to_path_buf()),
            Err(error) if error.kind() == std::io::ErrorKind::CrossesDevices => {
                // Stage on this destination's filesystem before atomic replacement.
                let staging = ExtractionStaging::new(
                    destination.parent().expect("validated path has parent"),
                )?;
                let local = staging.root.join("payload");
                // Preserve archive hardlinks when the earlier target was also
                // published onto this destination's mounted filesystem.
                let linked =
                    hardlink_target.is_some_and(|target| fs::hard_link(target, &local).is_ok());
                if !linked {
                    copy_verified_output(source, &local)?;
                }
                rename(&local, destination)?;
                destination.to_path_buf()
            }
            Err(error) => return Err(error.into()),
        },
    };
    remove_staged_output(source)?;
    Ok(published)
}

fn remove_staged_output(source: &Path) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileTypeExt;
        if fs::symlink_metadata(source)?.file_type().is_symlink_dir() {
            return fs::remove_dir(source);
        }
    }
    fs::remove_file(source)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> crate::scratch::Scratch {
        crate::scratch::case(&format!("rars-output-{name}"))
    }

    #[test]
    fn repeated_renames_resume_after_the_last_number_taken() {
        let mut taken = std::collections::HashSet::from([PathBuf::from("x(1)")]);
        let mut tried = Vec::new();
        let mut renames = RenameCounters::default();
        for _ in 0..3 {
            renames
                .claim(Path::new("x"), |path| {
                    tried.push(path.to_path_buf());
                    if taken.insert(path.to_path_buf()) {
                        Ok(())
                    } else {
                        Err(std::io::Error::from(std::io::ErrorKind::AlreadyExists))
                    }
                })
                .unwrap();
        }
        assert_eq!(tried, ["x", "x(1)", "x(2)", "x(3)"].map(PathBuf::from));
    }

    #[test]
    fn renamed_outputs_number_before_the_last_dot() {
        for (name, renamed) in [
            ("readme.txt", "readme(2).txt"),
            ("noext", "noext(2)"),
            (".hidden", "(2).hidden"),
            ("x.tar.gz", "x.tar(2).gz"),
        ] {
            assert_eq!(
                numbered(Path::new("out").join(name).as_path(), 2).unwrap(),
                Path::new("out").join(renamed)
            );
        }
    }

    #[test]
    fn verified_copy_fallback_keeps_no_overwrite_without_hardlinks() {
        let root = scratch("no-hardlink-publication");
        let source = root.join("source");
        let destination = root.join("destination");
        fs::write(&source, b"verified bytes").unwrap();
        let unsupported =
            |_: &Path, _: &Path| Err(std::io::Error::from(std::io::ErrorKind::Unsupported));
        publish_no_replace(&source, &destination, unsupported).unwrap();
        assert_eq!(fs::read(&destination).unwrap(), b"verified bytes");
        fs::write(&source, b"replacement").unwrap();
        assert_eq!(
            publish_no_replace(&source, &destination, unsupported)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::AlreadyExists
        );
        assert_eq!(fs::read(destination).unwrap(), b"verified bytes");
    }

    #[test]
    fn cross_device_publication_stages_beside_the_destination() {
        let root = scratch("cross-device-publication");
        let source = root.join("source");
        let parent = root.join("other-mount");
        fs::create_dir(&parent).unwrap();
        let destination = parent.join("destination");
        fs::write(&source, b"verified bytes").unwrap();
        fs::write(&destination, b"old contents").unwrap();
        let mut calls = 0;
        publish_verified_output_with_rename(
            &source,
            &destination,
            OverwritePolicy::Always,
            None,
            &mut RenameCounters::default(),
            |from, to| {
                calls += 1;
                if calls == 1 {
                    return Err(std::io::Error::from(std::io::ErrorKind::CrossesDevices));
                }
                assert!(from.starts_with(&parent));
                assert_eq!(fs::read(to).unwrap(), b"old contents");
                fs::rename(from, to)
            },
        )
        .unwrap();
        assert_eq!(calls, 2);
        assert_eq!(fs::read(&destination).unwrap(), b"verified bytes");
        assert!(!source.exists());
        assert_eq!(fs::read_dir(parent).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn cross_device_publication_preserves_archive_hardlinks() {
        use std::os::unix::fs::MetadataExt;
        for overwrite in [OverwritePolicy::Never, OverwritePolicy::Always] {
            let root = scratch("cross-device-hardlinks");
            let staging = ExtractionStaging::new(&root).unwrap();
            let source = staging.root.join("source");
            let source_link = staging.root.join("link");
            fs::write(&source, b"verified bytes").unwrap();
            fs::hard_link(&source, &source_link).unwrap();
            let parent = root.join("other-mount");
            fs::create_dir(&parent).unwrap();
            let target = parent.join("target");
            let destination = parent.join("link");
            // Force the ordinary target through the cross-device copy path.
            publish_verified_output_with_rename(
                &source,
                &target,
                OverwritePolicy::Always,
                None,
                &mut RenameCounters::default(),
                |from, to| {
                    if from.starts_with(&staging.root) {
                        Err(std::io::Error::from(std::io::ErrorKind::CrossesDevices))
                    } else {
                        fs::rename(from, to)
                    }
                },
            )
            .unwrap();
            publish_verified_output_with_rename(
                &source_link,
                &destination,
                overwrite,
                Some(&target),
                &mut RenameCounters::default(),
                |from, to| {
                    if from.starts_with(&staging.root) {
                        Err(std::io::Error::from(std::io::ErrorKind::CrossesDevices))
                    } else {
                        fs::rename(from, to)
                    }
                },
            )
            .unwrap();
            let original = fs::metadata(&target).unwrap();
            let linked = fs::metadata(&destination).unwrap();
            assert_eq!(
                (original.dev(), original.ino()),
                (linked.dev(), linked.ino())
            );
            assert_eq!(fs::read(destination).unwrap(), b"verified bytes");
        }
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn publication_cleans_staged_directory_symlinks() {
        for overwrite in [OverwritePolicy::Never, OverwritePolicy::Always] {
            let root = scratch("directory-symlink-publication");
            let directory = root.join("directory");
            fs::create_dir(&directory).unwrap();
            let source = root.join("source-link");
            let destination = root.join("published-link");
            let result = create_symlink(&directory, &source, true);
            #[cfg(windows)]
            if result
                .as_ref()
                .is_err_and(|error| error.raw_os_error() == Some(1314))
            {
                // Windows hosts without symlink privileges cannot exercise this API.
                return;
            }
            result.unwrap();
            let mut calls = 0;
            publish_verified_output_with_rename(
                &source,
                &destination,
                overwrite,
                None,
                &mut RenameCounters::default(),
                |from, to| {
                    calls += 1;
                    if calls == 1 {
                        Err(std::io::Error::from(std::io::ErrorKind::CrossesDevices))
                    } else {
                        fs::rename(from, to)
                    }
                },
            )
            .unwrap();
            assert!(fs::symlink_metadata(source).is_err());
            assert_eq!(fs::read_link(destination).unwrap(), directory);
        }
    }

    #[test]
    fn alias_checks_return_only_existing_destination_identities() {
        let root = scratch("alias-identities");
        let staging = ExtractionStaging::new(&root).unwrap();
        let directory = root.join("ordinary");
        fs::create_dir(&directory).unwrap();
        let file = directory.join("file");
        fs::write(&file, b"ordinary contents").unwrap();
        for path in [&directory, &file] {
            assert_eq!(
                staging.reject_alias(path).unwrap(),
                Some(fs::canonicalize(path).unwrap())
            );
        }
        assert_eq!(
            staging
                .reject_alias(&directory.join("missing/child"))
                .unwrap(),
            None
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            assert_eq!(staging.reject_alias(&file.join("child")).unwrap(), None);
            let dangling = root.join("dangling");
            symlink(root.join("absent"), &dangling).unwrap();
            assert_eq!(staging.reject_alias(&dangling).unwrap(), None);
            let alias = root.join("ordinary-alias");
            symlink(&file, &alias).unwrap();
            assert_eq!(
                staging.reject_alias(&alias).unwrap(),
                Some(fs::canonicalize(&file).unwrap())
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn alias_checks_reject_missing_descendants_of_a_staging_symlink() {
        use std::os::unix::fs::symlink;
        let root = scratch("missing-staging-alias");
        let staging = ExtractionStaging::new(&root).unwrap();
        let alias = root.join("alias");
        symlink(&staging.root, &alias).unwrap();
        // The first check both resolves the staging root and walks past two
        // missing components to find the alias. Repeat with the cached root.
        for path in [alias.join("missing/child"), alias, staging.root.clone()] {
            assert!(matches!(
                staging.reject_alias(&path),
                Err(Error::InvalidHeader(
                    "archive path conflicts with extraction storage"
                ))
            ));
        }
    }

    #[cfg(unix)]
    #[test]
    fn alias_checks_propagate_loops_and_permission_errors() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let root = scratch("alias-errors");
        let staging = ExtractionStaging::new(&root).unwrap();
        let cycle = root.join("cycle");
        symlink("cycle", &cycle).unwrap();
        assert!(matches!(staging.reject_alias(&cycle), Err(Error::Io(_))));

        let locked = root.join("locked");
        fs::create_dir(&locked).unwrap();
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o600)).unwrap();
        let destination = locked.join("missing");
        let probe = fs::symlink_metadata(&destination);
        let result = staging.reject_alias(&destination);
        // Restore search permission before assertions, including on runners
        // that can bypass the mode bits.
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o700)).unwrap();
        match probe {
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                assert!(matches!(
                    result,
                    Err(Error::Io(error)) if error.kind == std::io::ErrorKind::PermissionDenied
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                eprintln!("permission-denial case unavailable on privileged runner");
                assert_eq!(result.unwrap(), None);
            }
            other => panic!("unexpected permission probe: {other:?}"),
        }
    }

    #[test]
    fn alias_checks_retry_a_failed_initial_root_resolution() {
        let root = scratch("alias-resolution-retry");
        let staging = ExtractionStaging::new(&root).unwrap();
        let ordinary = root.join("ordinary");
        fs::write(&ordinary, b"ordinary contents").unwrap();
        fs::remove_dir(&staging.root).unwrap();
        assert!(matches!(staging.reject_alias(&ordinary), Err(Error::Io(_))));
        fs::create_dir(&staging.root).unwrap();
        assert_eq!(
            staging.reject_alias(&ordinary).unwrap(),
            Some(fs::canonicalize(&ordinary).unwrap())
        );
        #[cfg(unix)]
        {
            let alias = root.join("alias");
            std::os::unix::fs::symlink(&staging.root, &alias).unwrap();
            assert!(matches!(
                staging.reject_alias(&alias.join("missing/child")),
                Err(Error::InvalidHeader(
                    "archive path conflicts with extraction storage"
                ))
            ));
        }
    }
}

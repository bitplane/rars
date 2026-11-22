//! An output directory walked by descriptor. Each directory is opened once,
//! without following a symlink, and later entries are created and renamed
//! relative to it, so a member costs a few system calls and a symlink planted
//! during the extraction is never written through.
//! Shared by the CLI; not part of the stable API.

use crate::output_staging::{FileIdentity, OverwritePolicy, RenameCounters};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// What one entry under a tree is, without following a final symlink.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TreeEntry {
    Missing,
    Symlink,
    Directory(FileIdentity),
    Other(FileIdentity),
}

#[cfg(any(target_vendor = "apple", target_os = "linux", target_os = "android"))]
pub use imp::OutputTree;

#[cfg(not(any(target_vendor = "apple", target_os = "linux", target_os = "android")))]
pub use unsupported::OutputTree;

#[cfg(any(target_vendor = "apple", target_os = "linux", target_os = "android"))]
mod imp {
    use super::*;
    use crate::Error;
    use rustix::fs::{AtFlags, FileType, Mode, OFlags, RenameFlags, Stat, Timespec, Timestamps};
    use rustix::io::Errno;
    use std::ffi::{OsStr, OsString};
    use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
    use std::path::Component;

    /// Directories below this depth are opened for each use instead of kept.
    const CACHED_DEPTH: usize = 32;

    pub struct OutputTree {
        root: OwnedFd,
        root_identity: FileIdentity,
        /// A directory no path in this tree may reach: the extraction storage.
        forbidden: Option<FileIdentity>,
        /// The directories of the last path walked, outermost first.
        chain: Vec<(OsString, OwnedFd)>,
        /// The directory a walk deeper than the chain ended in.
        deep: Option<OwnedFd>,
    }

    #[allow(clippy::unnecessary_cast)]
    fn identity(stat: &Stat) -> FileIdentity {
        FileIdentity::from_inode(stat.st_dev as u64, stat.st_ino as u64)
    }

    fn crosses_symlink() -> Error {
        Error::UnsafePath("unsafe archive path crosses symlink")
    }

    fn conflicts_with_storage() -> Error {
        Error::InvalidHeader("archive path conflicts with extraction storage")
    }

    fn split(relative: &Path) -> crate::Result<(Vec<&OsStr>, &OsStr)> {
        let mut parts = Vec::new();
        for component in relative.components() {
            let Component::Normal(part) = component else {
                return Err(Error::UnsafePath("unsafe archive path"));
            };
            parts.push(part);
        }
        let name = parts
            .pop()
            .ok_or(Error::UnsafePath("unsafe archive path"))?;
        Ok((parts, name))
    }

    fn lstat_at(dir: BorrowedFd<'_>, name: &OsStr) -> std::io::Result<Option<Stat>> {
        match rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => Ok(Some(stat)),
            Err(Errno::NOENT) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    /// Whether a rename failed for want of support rather than because of what is there.
    fn unsupported(error: &std::io::Error) -> bool {
        matches!(
            error.raw_os_error().map(Errno::from_raw_os_error),
            Some(Errno::XDEV | Errno::INVAL | Errno::NOSYS | Errno::OPNOTSUPP)
        )
    }

    fn timespec(time: SystemTime) -> Timespec {
        match time.duration_since(SystemTime::UNIX_EPOCH) {
            Ok(after) => Timespec {
                tv_sec: after.as_secs() as i64,
                tv_nsec: after.subsec_nanos() as _,
            },
            Err(before) => {
                let before = before.duration();
                let seconds = -(before.as_secs() as i64);
                match before.subsec_nanos() {
                    0 => Timespec {
                        tv_sec: seconds,
                        tv_nsec: 0,
                    },
                    nanos => Timespec {
                        tv_sec: seconds - 1,
                        tv_nsec: (1_000_000_000 - nanos) as _,
                    },
                }
            }
        }
    }

    impl OutputTree {
        /// Opens `root`, which may itself be reached through a symlink. `None`
        /// when it does not exist yet.
        pub fn open(root: &Path) -> std::io::Result<Option<Self>> {
            let root = match rustix::fs::open(
                root,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            ) {
                Ok(root) => root,
                Err(Errno::NOENT) => return Ok(None),
                Err(error) => return Err(error.into()),
            };
            let root_identity = identity(&rustix::fs::fstat(&root)?);
            Ok(Some(Self {
                root,
                root_identity,
                forbidden: None,
                chain: Vec::new(),
                deep: None,
            }))
        }

        pub fn identity(&self) -> FileIdentity {
            self.root_identity
        }

        /// Refuses any path in this tree that reaches `directory`.
        pub fn forbid(&mut self, directory: FileIdentity) {
            self.forbidden = Some(directory);
        }

        /// Drops the cached directories, after something else changed the tree.
        pub fn forget(&mut self) {
            self.chain.clear();
            self.deep = None;
        }

        fn check(&self, identity: FileIdentity) -> crate::Result<()> {
            if self.forbidden == Some(identity) {
                return Err(conflicts_with_storage());
            }
            Ok(())
        }

        /// Opens one directory below `parent`, creating it first if asked. `None` when it is missing.
        fn open_dir(
            &self,
            parent: BorrowedFd<'_>,
            name: &OsStr,
            create: bool,
        ) -> crate::Result<Option<OwnedFd>> {
            if create {
                match rustix::fs::mkdirat(parent, name, Mode::from_raw_mode(0o777)) {
                    Ok(()) | Err(Errno::EXIST) => {}
                    Err(error) => return Err(std::io::Error::from(error).into()),
                }
            }
            let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
            let directory = match rustix::fs::openat(parent, name, flags, Mode::empty()) {
                Ok(directory) => directory,
                Err(Errno::NOENT) if !create => return Ok(None),
                Err(error @ (Errno::LOOP | Errno::NOTDIR | Errno::MLINK)) => {
                    if lstat_at(parent, name)?
                        .is_some_and(|stat| FileType::from_raw_mode(stat.st_mode as _).is_symlink())
                    {
                        return Err(crosses_symlink());
                    }
                    // Below a file nothing exists yet; creating it is what fails.
                    if error == Errno::NOTDIR && !create {
                        return Ok(None);
                    }
                    return Err(std::io::Error::from(error).into());
                }
                Err(error) => return Err(std::io::Error::from(error).into()),
            };
            self.check(identity(
                &rustix::fs::fstat(&directory).map_err(std::io::Error::from)?,
            ))?;
            Ok(Some(directory))
        }

        /// The directory `parts` names, walking from the deepest cached one.
        fn dir(&mut self, parts: &[&OsStr], create: bool) -> crate::Result<Option<BorrowedFd<'_>>> {
            let kept = self
                .chain
                .iter()
                .zip(parts)
                .take_while(|((cached, _), part)| cached.as_os_str() == **part)
                .count();
            self.chain.truncate(kept);
            self.deep = None;
            for (depth, part) in parts.iter().enumerate().skip(kept) {
                let parent = self.current();
                let Some(directory) = self.open_dir(parent, part, create)? else {
                    return Ok(None);
                };
                if depth < CACHED_DEPTH {
                    self.chain.push((part.to_os_string(), directory));
                } else {
                    self.deep = Some(directory);
                }
            }
            Ok(Some(self.current()))
        }

        /// What `relative` is, refusing a symlink on the way to it.
        pub fn lstat(&mut self, relative: &Path) -> crate::Result<TreeEntry> {
            let (parts, name) = split(relative)?;
            let Some(parent) = self.dir(&parts, false)? else {
                return Ok(TreeEntry::Missing);
            };
            let Some(stat) = lstat_at(parent, name)? else {
                return Ok(TreeEntry::Missing);
            };
            let file_type = FileType::from_raw_mode(stat.st_mode as _);
            if file_type.is_symlink() {
                return Ok(TreeEntry::Symlink);
            }
            let identity = identity(&stat);
            self.check(identity)?;
            Ok(if file_type.is_dir() {
                TreeEntry::Directory(identity)
            } else {
                TreeEntry::Other(identity)
            })
        }

        /// The identity of what `relative` names, following a final symlink as
        /// [`FileIdentity::of`] does. `None` when it does not exist.
        pub fn identity_of(&mut self, relative: &Path) -> crate::Result<Option<FileIdentity>> {
            let (parts, name) = split(relative)?;
            let Some(parent) = self.dir(&parts, false)? else {
                return Ok(None);
            };
            match rustix::fs::statat(parent, name, AtFlags::empty()) {
                Ok(stat) => Ok(Some(identity(&stat))),
                Err(Errno::NOENT) => Ok(None),
                Err(error) => Err(std::io::Error::from(error).into()),
            }
        }

        /// Creates the directory `relative` and any missing parents.
        pub fn create_dirs(&mut self, relative: &Path) -> crate::Result<FileIdentity> {
            let (mut parts, name) = split(relative)?;
            parts.push(name);
            self.dir(&parts, true)?;
            let stat = rustix::fs::fstat(self.current()).map_err(std::io::Error::from)?;
            Ok(identity(&stat))
        }

        /// The directory the last walk ended in.
        fn current(&self) -> BorrowedFd<'_> {
            match (&self.deep, self.chain.last()) {
                (Some(deep), _) => deep.as_fd(),
                (None, Some((_, cached))) => cached.as_fd(),
                (None, None) => self.root.as_fd(),
            }
        }

        /// Creates a new file at `relative`, and any missing parents. An
        /// existing entry of any kind fails with `AlreadyExists`.
        pub fn create_file(&mut self, relative: &Path) -> crate::Result<std::fs::File> {
            let (parts, name) = split(relative)?;
            let parent = self.dir(&parts, true)?.expect("created parents exist");
            let flags =
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
            let file = rustix::fs::openat(parent, name, flags, Mode::from_raw_mode(0o666))
                .map_err(std::io::Error::from)?;
            Ok(std::fs::File::from(file))
        }

        /// Sets a file's modified time and mode, leaving its access time alone.
        pub fn set_metadata(
            &mut self,
            relative: &Path,
            modified: Option<SystemTime>,
            mode: Option<u32>,
        ) -> crate::Result<()> {
            let (parts, name) = split(relative)?;
            let parent = self
                .dir(&parts, false)?
                .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))?;
            if let Some(modified) = modified {
                let times = Timestamps {
                    last_access: Timespec {
                        tv_sec: 0,
                        tv_nsec: rustix::fs::UTIME_OMIT,
                    },
                    last_modification: timespec(modified),
                };
                rustix::fs::utimensat(parent, name, &times, AtFlags::SYMLINK_NOFOLLOW)
                    .map_err(std::io::Error::from)?;
            }
            if let Some(mode) = mode {
                rustix::fs::chmodat(
                    parent,
                    name,
                    Mode::from_raw_mode(mode as _),
                    AtFlags::empty(),
                )
                .map_err(std::io::Error::from)?;
            }
            Ok(())
        }

        /// Renames `relative` here to `to_relative` in `to` by the overwrite
        /// policy, returning where it landed. `destination` is
        /// `to_relative`'s full path, which `Rename` numbers. `None` when the
        /// filesystem cannot do it, leaving the caller to publish by path.
        pub fn publish(
            &mut self,
            relative: &Path,
            to: &mut OutputTree,
            to_relative: &Path,
            destination: &Path,
            overwrite: OverwritePolicy,
            renames: &mut RenameCounters,
        ) -> crate::Result<Option<PathBuf>> {
            let (parts, name) = split(relative)?;
            let (to_parts, to_name) = split(to_relative)?;
            let from = self
                .dir(&parts, false)?
                .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))?;
            let into = to.dir(&to_parts, true)?.expect("created parents exist");
            let fell_back = std::cell::Cell::new(false);
            let renamed = |to_name: &OsStr, flags: RenameFlags| -> std::io::Result<()> {
                rustix::fs::renameat_with(from, name, into, to_name, flags).map_err(|error| {
                    let error = std::io::Error::from(error);
                    fell_back.set(fell_back.get() || unsupported(&error));
                    error
                })
            };
            let result = match overwrite {
                OverwritePolicy::Never => renamed(to_name, RenameFlags::NOREPLACE)
                    .map(|()| destination.to_path_buf())
                    .map_err(Error::from),
                OverwritePolicy::Always => renamed(to_name, RenameFlags::empty())
                    .map(|()| destination.to_path_buf())
                    .map_err(Error::from),
                OverwritePolicy::Rename => renames
                    .claim(destination, |candidate| {
                        renamed(
                            candidate.file_name().expect("output path has a name"),
                            RenameFlags::NOREPLACE,
                        )
                    })
                    .map(|(published, ())| published),
            };
            match result {
                Ok(published) => Ok(Some(published)),
                Err(_) if fell_back.get() => Ok(None),
                Err(error) => Err(error),
            }
        }
    }
}

#[cfg(not(any(target_vendor = "apple", target_os = "linux", target_os = "android")))]
mod unsupported {
    use super::*;

    /// Never constructed: [`OutputTree::open`] returns `None` here, and callers check paths instead.
    pub struct OutputTree(std::convert::Infallible);

    impl OutputTree {
        pub fn open(_root: &Path) -> std::io::Result<Option<Self>> {
            Ok(None)
        }

        pub fn identity(&self) -> FileIdentity {
            match self.0 {}
        }

        pub fn forbid(&mut self, _directory: FileIdentity) {
            match self.0 {}
        }

        pub fn forget(&mut self) {
            match self.0 {}
        }

        pub fn lstat(&mut self, _relative: &Path) -> crate::Result<TreeEntry> {
            match self.0 {}
        }

        pub fn identity_of(&mut self, _relative: &Path) -> crate::Result<Option<FileIdentity>> {
            match self.0 {}
        }

        pub fn create_dirs(&mut self, _relative: &Path) -> crate::Result<FileIdentity> {
            match self.0 {}
        }

        pub fn create_file(&mut self, _relative: &Path) -> crate::Result<std::fs::File> {
            match self.0 {}
        }

        pub fn set_metadata(
            &mut self,
            _relative: &Path,
            _modified: Option<SystemTime>,
            _mode: Option<u32>,
        ) -> crate::Result<()> {
            match self.0 {}
        }

        pub fn publish(
            &mut self,
            _relative: &Path,
            _to: &mut OutputTree,
            _to_relative: &Path,
            _destination: &Path,
            _overwrite: OverwritePolicy,
            _renames: &mut RenameCounters,
        ) -> crate::Result<Option<PathBuf>> {
            match self.0 {}
        }
    }
}

#[cfg(all(
    test,
    any(target_vendor = "apple", target_os = "linux", target_os = "android")
))]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn walks_refuse_symlinks_and_the_forbidden_directory() {
        let scratch = crate::scratch::case("output-tree-refusals");
        let root = scratch.join("root");
        let outside = scratch.join("outside");
        fs::create_dir_all(root.join("storage")).unwrap();
        fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("link")).unwrap();
        let mut tree = OutputTree::open(&root).unwrap().unwrap();
        let storage = OutputTree::open(&root.join("storage")).unwrap().unwrap();
        tree.forbid(storage.identity());

        let crosses = |result: crate::Result<()>| {
            matches!(
                result,
                Err(crate::Error::UnsafePath(
                    "unsafe archive path crosses symlink"
                ))
            )
        };
        assert_eq!(tree.lstat(Path::new("link")).unwrap(), TreeEntry::Symlink);
        assert!(crosses(tree.lstat(Path::new("link/file")).map(drop)));
        assert!(crosses(tree.create_file(Path::new("link/file")).map(drop)));
        assert!(crosses(tree.create_dirs(Path::new("link/dir")).map(drop)));
        assert!(matches!(
            tree.create_file(Path::new("storage/file")),
            Err(crate::Error::InvalidHeader(
                "archive path conflicts with extraction storage"
            ))
        ));
        assert_eq!(fs::read_dir(&outside).unwrap().count(), 0);

        tree.create_file(Path::new("a/b/file")).unwrap();
        assert!(matches!(
            tree.lstat(Path::new("a/b/file")).unwrap(),
            TreeEntry::Other(_)
        ));
        assert!(matches!(
            tree.create_file(Path::new("a/b/file")),
            Err(crate::Error::Io(error)) if error.kind == std::io::ErrorKind::AlreadyExists
        ));
        assert_eq!(
            tree.lstat(Path::new("a/b/file/below")).unwrap(),
            TreeEntry::Missing
        );
    }
}

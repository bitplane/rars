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

/// Whether [`OutputTree::open`] can open a tree on this platform.
pub const AVAILABLE: bool = cfg!(any(
    target_vendor = "apple",
    target_os = "linux",
    target_os = "android"
));

/// A file [`FileDir::open_in_place`] opened to write over.
pub struct InPlaceFile {
    pub file: std::fs::File,
    pub identity: FileIdentity,
    /// Its length when opened: it is not truncated.
    pub len: u64,
}

/// A member's file being written. Dropped, it hands the file over to `done`
/// rather than closing it, so that its time and mode can be set through its
/// own descriptor once it verifies.
pub struct HeldFile {
    file: Option<std::fs::File>,
    done: std::sync::Arc<std::sync::OnceLock<std::fs::File>>,
}

impl HeldFile {
    pub fn new(file: std::fs::File) -> (Self, std::sync::Arc<std::sync::OnceLock<std::fs::File>>) {
        let done = std::sync::Arc::default();
        let writer = Self {
            file: Some(file),
            done: std::sync::Arc::clone(&done),
        };
        (writer, done)
    }

    fn file(&mut self) -> &mut std::fs::File {
        self.file.as_mut().expect("held until dropped")
    }
}

impl std::io::Write for HeldFile {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.file().write(buf)
    }

    fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        self.file().write_all(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file().flush()
    }
}

impl Drop for HeldFile {
    fn drop(&mut self) {
        if let Some(file) = self.file.take() {
            let _ = self.done.set(file);
        }
    }
}

#[cfg(any(target_vendor = "apple", target_os = "linux", target_os = "android"))]
pub use imp::{file_identity, FileDir, OutputTree};

#[cfg(not(any(target_vendor = "apple", target_os = "linux", target_os = "android")))]
pub use unsupported::{file_identity, FileDir, OutputTree};

#[cfg(any(target_vendor = "apple", target_os = "linux", target_os = "android"))]
mod imp {
    use super::*;
    use crate::Error;
    use rustix::fs::{AtFlags, FileType, Mode, OFlags, RenameFlags, Stat, Timespec, Timestamps};
    use rustix::io::Errno;
    use std::collections::HashSet;
    use std::ffi::{OsStr, OsString};
    use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
    use std::path::Component;
    use std::sync::Arc;

    /// Directories below this depth are opened for each use instead of kept.
    const CACHED_DEPTH: usize = 32;
    /// Walks kept at once. Extraction alternates between the member it is
    /// opening and an earlier one it is publishing, often in different
    /// directories, and a single walk would reopen both every time.
    const CURSORS: usize = 2;

    /// An open directory and its identity.
    type Opened = (Arc<OwnedFd>, FileIdentity);

    /// One cached walk from the root.
    #[derive(Default)]
    struct Cursor {
        /// The directories of the last path walked, outermost first.
        chain: Vec<(OsString, Opened)>,
        /// The directory a walk deeper than the chain ended in.
        deep: Option<Opened>,
    }

    impl Cursor {
        /// How many of `parts` this walk already holds open.
        fn kept(&self, parts: &[&OsStr]) -> usize {
            self.chain
                .iter()
                .zip(parts)
                .take_while(|((cached, _), part)| cached.as_os_str() == **part)
                .count()
        }

        /// The directory this walk holds `depth` levels down, or `root`.
        fn at<'a>(&'a self, depth: usize, root: &'a Opened) -> &'a Opened {
            match depth.checked_sub(1) {
                Some(index) => &self.chain[index].1,
                None => root,
            }
        }

        /// The directory this walk ended in, or `root`.
        fn end<'a>(&'a self, root: &'a Opened) -> &'a Opened {
            match &self.deep {
                Some(deep) => deep,
                None => self.at(self.chain.len(), root),
            }
        }
    }

    /// A directory new files can be created in from any thread.
    #[derive(Clone)]
    pub struct FileDir(Arc<OwnedFd>);

    impl FileDir {
        /// Creates a new file called `name` with the permission bits `mode`,
        /// less what the umask clears. An existing entry of any kind fails
        /// with `AlreadyExists`.
        pub fn create_file(&self, name: &OsStr, mode: u32) -> std::io::Result<std::fs::File> {
            create_file_at(self.0.as_fd(), name, mode)
        }
    }

    impl FileDir {
        /// Creates a new file for `destination` here, as [`Self::create_file`]
        /// does, trying `name(N).ext` upwards while the name is taken, as
        /// `Rename` does. Returns where it was created.
        pub fn create_numbered(
            &self,
            destination: &Path,
            mode: u32,
            renames: &mut RenameCounters,
        ) -> crate::Result<(PathBuf, std::fs::File)> {
            renames.claim(destination, |candidate| {
                self.create_file(candidate.file_name().expect("output path has a name"), mode)
            })
        }

        /// Opens `name` here to write over, creating it with the permission
        /// bits `mode` if it is missing. Only a regular file with one link is
        /// opened: a symlink, a FIFO, a hard-linked file or anything else is
        /// refused, and never written through. It is not truncated.
        pub fn open_in_place(&self, name: &OsStr, mode: u32) -> std::io::Result<InPlaceFile> {
            // O_NONBLOCK fails a FIFO with no reader instead of waiting for one.
            let flags = OFlags::WRONLY
                | OFlags::CREATE
                | OFlags::NOFOLLOW
                | OFlags::NONBLOCK
                | OFlags::CLOEXEC;
            let file =
                rustix::fs::openat(self.0.as_fd(), name, flags, Mode::from_raw_mode(mode as _))
                    .map_err(|error| match error {
                        Errno::LOOP | Errno::NXIO => crate::output_staging::refused_in_place(),
                        error => error.into(),
                    })?;
            let stat = rustix::fs::fstat(&file)?;
            if !FileType::from_raw_mode(stat.st_mode as _).is_file() || stat.st_nlink > 1 {
                return Err(crate::output_staging::refused_in_place());
            }
            Ok(InPlaceFile {
                file: std::fs::File::from(file),
                identity: identity(&stat),
                len: stat.st_size as u64,
            })
        }

        /// What `name` here is, without following a symlink.
        pub fn entry(&self, name: &OsStr) -> std::io::Result<TreeEntry> {
            let Some(stat) = lstat_at(self.0.as_fd(), name)? else {
                return Ok(TreeEntry::Missing);
            };
            let file_type = FileType::from_raw_mode(stat.st_mode as _);
            Ok(if file_type.is_symlink() {
                TreeEntry::Symlink
            } else if file_type.is_dir() {
                TreeEntry::Directory(identity(&stat))
            } else {
                TreeEntry::Other(identity(&stat))
            })
        }
    }

    /// The identity of an open file.
    pub fn file_identity(file: &std::fs::File) -> std::io::Result<FileIdentity> {
        Ok(identity(&rustix::fs::fstat(file)?))
    }

    fn create_file_at(
        parent: BorrowedFd<'_>,
        name: &OsStr,
        mode: u32,
    ) -> std::io::Result<std::fs::File> {
        let flags =
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let file = rustix::fs::openat(parent, name, flags, Mode::from_raw_mode(mode as _))?;
        Ok(std::fs::File::from(file))
    }

    pub struct OutputTree {
        root: Opened,
        /// A directory no path in this tree may reach: the extraction storage.
        forbidden: Option<FileIdentity>,
        cursors: [Cursor; CURSORS],
        /// The cursor the last walk used.
        last: usize,
        /// A directory the last walk found missing, until a walk may create
        /// one: what is below it is missing too. Extraction looks up each
        /// member's destination before the directory holding it is made.
        missing: Vec<OsString>,
        /// The directories walks have created.
        created: HashSet<FileIdentity>,
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

    fn check(forbidden: Option<FileIdentity>, identity: FileIdentity) -> crate::Result<()> {
        if forbidden == Some(identity) {
            return Err(conflicts_with_storage());
        }
        Ok(())
    }

    /// Opens one directory below `parent`, creating it first if asked, and
    /// adding it to `created` if it did. `None` when it is missing.
    fn open_dir(
        forbidden: Option<FileIdentity>,
        created: &mut HashSet<FileIdentity>,
        parent: BorrowedFd<'_>,
        name: &OsStr,
        create: bool,
    ) -> crate::Result<Option<Opened>> {
        let made = create
            && match rustix::fs::mkdirat(parent, name, Mode::from_raw_mode(0o777)) {
                Ok(()) => true,
                Err(Errno::EXIST) => false,
                Err(error) => return Err(std::io::Error::from(error).into()),
            };
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
        let identity = identity(&rustix::fs::fstat(&directory).map_err(std::io::Error::from)?);
        check(forbidden, identity)?;
        if made {
            created.insert(identity);
        }
        Ok(Some((Arc::new(directory), identity)))
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
                root: (Arc::new(root), root_identity),
                forbidden: None,
                cursors: Default::default(),
                last: 0,
                missing: Vec::new(),
                created: HashSet::new(),
            }))
        }

        pub fn identity(&self) -> FileIdentity {
            self.root.1
        }

        /// Refuses any path in this tree that reaches `directory`.
        pub fn forbid(&mut self, directory: FileIdentity) {
            self.forbidden = Some(directory);
        }

        /// Whether a walk here created the directory `identity`.
        pub fn created(&self, identity: &FileIdentity) -> bool {
            self.created.contains(identity)
        }

        /// Drops the cached directories, after something else changed the tree.
        pub fn forget(&mut self) {
            self.cursors = Default::default();
            self.missing.clear();
        }

        fn check(&self, identity: FileIdentity) -> crate::Result<()> {
            check(self.forbidden, identity)
        }

        /// The directory `parts` names and its identity. A directory a cursor
        /// holds is used as it is, leaving what that cursor holds below it.
        /// Any other walk moves the cursor whose end was used less recently,
        /// starting from the longest part of the path either cursor holds, so
        /// two walks that alternate keep a cursor each.
        fn dir(
            &mut self,
            parts: &[&OsStr],
            create: bool,
        ) -> crate::Result<Option<(BorrowedFd<'_>, FileIdentity)>> {
            Ok(self
                .walk(parts, create)?
                .map(|(directory, identity)| (directory.as_fd(), *identity)))
        }

        /// As [`Self::dir`], keeping the directory's handle.
        fn walk(&mut self, parts: &[&OsStr], create: bool) -> crate::Result<Option<&Opened>> {
            if !create
                && !self.missing.is_empty()
                && parts.len() >= self.missing.len()
                && self
                    .missing
                    .iter()
                    .zip(parts)
                    .all(|(missing, part)| missing == part)
            {
                return Ok(None);
            }
            let kept = self.cursors.each_ref().map(|cursor| cursor.kept(parts));
            if let Some(index) = (0..CURSORS).find(|&index| kept[index] == parts.len()) {
                let cursor = &self.cursors[index];
                if parts.len() == cursor.chain.len() && cursor.deep.is_none() {
                    self.last = index;
                }
                return Ok(Some(cursor.at(parts.len(), &self.root)));
            }
            let target = (self.last + 1) % CURSORS;
            let source = (0..CURSORS)
                .max_by_key(|&index| (kept[index], index == target))
                .expect("there is a cursor");
            let kept = kept[source];
            if source != target {
                let prefix = self.cursors[source].chain[..kept].to_vec();
                self.cursors[target].chain = prefix;
            }
            self.last = target;
            if create {
                self.missing.clear();
            }
            let cursor = &mut self.cursors[target];
            cursor.chain.truncate(kept);
            cursor.deep = None;
            for (depth, part) in parts.iter().enumerate().skip(kept) {
                let parent = cursor.end(&self.root).0.as_fd();
                let Some(directory) =
                    open_dir(self.forbidden, &mut self.created, parent, part, create)?
                else {
                    self.missing = parts[..=depth]
                        .iter()
                        .map(|part| part.to_os_string())
                        .collect();
                    return Ok(None);
                };
                if depth < CACHED_DEPTH {
                    cursor.chain.push((part.to_os_string(), directory));
                } else {
                    cursor.deep = Some(directory);
                }
            }
            Ok(Some(cursor.end(&self.root)))
        }

        /// What `relative` is, refusing a symlink on the way to it.
        pub fn lstat(&mut self, relative: &Path) -> crate::Result<TreeEntry> {
            self.lstat_with(relative, false)
        }

        /// As [`Self::lstat`], but [`TreeEntry::Missing`] without looking
        /// when a walk here created the directory holding `relative`. Nothing
        /// was there before this run, so what is there now was put there
        /// during it: by this run, or by something racing it that only a
        /// publication refusing to follow or replace it keeps out.
        pub fn lstat_unless_created(&mut self, relative: &Path) -> crate::Result<TreeEntry> {
            self.lstat_with(relative, true)
        }

        fn lstat_with(&mut self, relative: &Path, skip_created: bool) -> crate::Result<TreeEntry> {
            let (parts, name) = split(relative)?;
            let Some((parent, parent_identity)) = self.walk(&parts, false)? else {
                return Ok(TreeEntry::Missing);
            };
            let (parent, parent_identity) = (Arc::clone(parent), *parent_identity);
            if skip_created && self.created.contains(&parent_identity) {
                return Ok(TreeEntry::Missing);
            }
            let Some(stat) = lstat_at(parent.as_fd(), name)? else {
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
            let Some((parent, _)) = self.dir(&parts, false)? else {
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
            let (_, identity) = self.dir(&parts, true)?.expect("created directories exist");
            Ok(identity)
        }

        /// Creates the directory `relative` and any missing parents, for
        /// creating files in from other threads.
        pub fn file_dir(&mut self, relative: &Path) -> crate::Result<FileDir> {
            let (mut parts, name) = split(relative)?;
            parts.push(name);
            let (directory, _) = self.walk(&parts, true)?.expect("created directories exist");
            Ok(FileDir(Arc::clone(directory)))
        }

        /// Creates the directories holding `relative`, and returns the one
        /// it goes in and that directory's identity.
        pub fn parent_dir(&mut self, relative: &Path) -> crate::Result<(FileDir, FileIdentity)> {
            let (parts, _) = split(relative)?;
            let (directory, identity) =
                self.walk(&parts, true)?.expect("created directories exist");
            Ok((FileDir(Arc::clone(directory)), *identity))
        }

        /// Creates a new file at `relative`, and any missing parents. An
        /// existing entry of any kind fails with `AlreadyExists`.
        pub fn create_file(&mut self, relative: &Path) -> crate::Result<std::fs::File> {
            let (parts, name) = split(relative)?;
            let (parent, _) = self.dir(&parts, true)?.expect("created parents exist");
            Ok(create_file_at(parent, name, 0o666)?)
        }
    }

    impl FileDir {
        /// Sets the modified time and mode of the file `name` here, leaving
        /// its access time alone.
        pub fn set_metadata(
            &self,
            name: &OsStr,
            modified: Option<SystemTime>,
            mode: Option<u32>,
        ) -> crate::Result<()> {
            let parent = self.0.as_fd();
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

        /// Renames `name` here to `to_relative` in `to` by the overwrite
        /// policy, returning where it landed. `destination` is
        /// `to_relative`'s full path, which `Rename` numbers. `None` when the
        /// filesystem cannot do it, leaving the caller to publish by path.
        pub fn publish(
            &self,
            name: &OsStr,
            to: &mut OutputTree,
            to_relative: &Path,
            destination: &Path,
            overwrite: OverwritePolicy,
            renames: &mut RenameCounters,
        ) -> crate::Result<Option<PathBuf>> {
            let (to_parts, to_name) = split(to_relative)?;
            let from = self.0.as_fd();
            let (into, _) = to.dir(&to_parts, true)?.expect("created parents exist");
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
    use std::ffi::OsStr;

    /// Never constructed: [`OutputTree::open`] returns `None` here, and callers check paths instead.
    pub struct OutputTree(std::convert::Infallible);

    /// Never constructed, as [`OutputTree`].
    #[derive(Clone)]
    pub struct FileDir(std::convert::Infallible);

    /// Never called: no tree opens a file here.
    pub fn file_identity(_file: &std::fs::File) -> std::io::Result<FileIdentity> {
        Err(std::io::ErrorKind::Unsupported.into())
    }

    impl FileDir {
        pub fn create_file(&self, _name: &OsStr, _mode: u32) -> std::io::Result<std::fs::File> {
            match self.0 {}
        }

        pub fn create_numbered(
            &self,
            _destination: &Path,
            _mode: u32,
            _renames: &mut RenameCounters,
        ) -> crate::Result<(PathBuf, std::fs::File)> {
            match self.0 {}
        }

        pub fn open_in_place(&self, _name: &OsStr, _mode: u32) -> std::io::Result<InPlaceFile> {
            match self.0 {}
        }

        pub fn entry(&self, _name: &OsStr) -> std::io::Result<TreeEntry> {
            match self.0 {}
        }

        pub fn set_metadata(
            &self,
            _name: &OsStr,
            _modified: Option<SystemTime>,
            _mode: Option<u32>,
        ) -> crate::Result<()> {
            match self.0 {}
        }

        pub fn publish(
            &self,
            _name: &OsStr,
            _to: &mut OutputTree,
            _to_relative: &Path,
            _destination: &Path,
            _overwrite: OverwritePolicy,
            _renames: &mut RenameCounters,
        ) -> crate::Result<Option<PathBuf>> {
            match self.0 {}
        }
    }

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

        pub fn created(&self, _identity: &FileIdentity) -> bool {
            match self.0 {}
        }

        pub fn forget(&mut self) {
            match self.0 {}
        }

        pub fn lstat(&mut self, _relative: &Path) -> crate::Result<TreeEntry> {
            match self.0 {}
        }

        pub fn lstat_unless_created(&mut self, _relative: &Path) -> crate::Result<TreeEntry> {
            match self.0 {}
        }

        pub fn identity_of(&mut self, _relative: &Path) -> crate::Result<Option<FileIdentity>> {
            match self.0 {}
        }

        pub fn create_dirs(&mut self, _relative: &Path) -> crate::Result<FileIdentity> {
            match self.0 {}
        }

        pub fn file_dir(&mut self, _relative: &Path) -> crate::Result<FileDir> {
            match self.0 {}
        }

        pub fn parent_dir(&mut self, _relative: &Path) -> crate::Result<(FileDir, FileIdentity)> {
            match self.0 {}
        }

        pub fn create_file(&mut self, _relative: &Path) -> crate::Result<std::fs::File> {
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

    #[test]
    fn files_opened_in_place_are_only_ever_regular_files_with_one_link() {
        use std::ffi::OsStr;
        use std::io::Write;

        let scratch = crate::scratch::case("output-tree-in-place");
        let root = scratch.join("root");
        let outside = scratch.join("outside");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("target"), b"outside").unwrap();
        let mut tree = OutputTree::open(&root).unwrap().unwrap();

        // The parent is made and recorded as made by this walk.
        let (dir, identity) = tree.parent_dir(Path::new("a/b/file")).unwrap();
        assert!(tree.created(&identity));
        let (_, again) = tree.parent_dir(Path::new("a/b/other")).unwrap();
        assert_eq!(again, identity);
        let (_, top) = tree.parent_dir(Path::new("top")).unwrap();
        assert_eq!(top, tree.identity());
        assert!(!tree.created(&top));

        // A file opened in place is the one there, not truncated.
        let existing = root.join("a/b/file");
        fs::write(&existing, b"old contents").unwrap();
        let opened = dir.open_in_place(OsStr::new("file"), 0o644).unwrap();
        assert_eq!(opened.len, 12);
        assert_eq!(
            Some(opened.identity),
            tree.identity_of(Path::new("a/b/file")).unwrap()
        );
        drop(opened);
        // A missing one is created.
        let mut created = dir.open_in_place(OsStr::new("new"), 0o600).unwrap();
        assert_eq!(created.len, 0);
        created.file.write_all(b"new").unwrap();
        assert_eq!(fs::read(root.join("a/b/new")).unwrap(), b"new");

        // A symlink, a hard link or a FIFO is refused and left alone.
        std::os::unix::fs::symlink(outside.join("target"), root.join("a/b/link")).unwrap();
        fs::hard_link(outside.join("target"), root.join("a/b/hard")).unwrap();
        assert!(std::process::Command::new("mkfifo")
            .arg(root.join("a/b/fifo"))
            .status()
            .unwrap()
            .success());
        for name in ["link", "hard", "fifo"] {
            let refused = dir.open_in_place(OsStr::new(name), 0o644).map(drop);
            assert!(
                refused
                    .as_ref()
                    .is_err_and(|error| error.to_string().contains("refusing to write in place")),
                "{name}: {refused:?}"
            );
        }
        assert_eq!(fs::read(outside.join("target")).unwrap(), b"outside");
        assert_eq!(dir.entry(OsStr::new("link")).unwrap(), TreeEntry::Symlink);
        assert!(matches!(
            dir.entry(OsStr::new("hard")).unwrap(),
            TreeEntry::Other(_)
        ));
        assert_eq!(
            dir.entry(OsStr::new("missing")).unwrap(),
            TreeEntry::Missing
        );

        // Numbered creation steps past any entry, a symlink included.
        let mut renames = RenameCounters::default();
        let (path, _) = dir
            .create_numbered(&root.join("a/b/link"), 0o644, &mut renames)
            .unwrap();
        assert_eq!(path, root.join("a/b/link(1)"));
        assert!(fs::symlink_metadata(root.join("a/b/link(1)"))
            .unwrap()
            .is_file());
        assert_eq!(fs::read_dir(&outside).unwrap().count(), 1);
    }

    #[test]
    fn staged_files_publish_through_walks_that_refuse_planted_symlinks() {
        use std::ffi::OsStr;
        use std::io::Write;

        let scratch = crate::scratch::case("output-tree-staged-files");
        let root = scratch.join("root");
        let outside = scratch.join("outside");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(scratch.join("storage")).unwrap();
        fs::create_dir_all(&outside).unwrap();
        let mut tree = OutputTree::open(&root).unwrap().unwrap();
        let mut storage = OutputTree::open(&scratch.join("storage")).unwrap().unwrap();
        let files = storage.file_dir(Path::new("files")).unwrap();
        let mut renames = RenameCounters::default();
        let mut publish = |tree: &mut OutputTree, name: &str, to: &str, overwrite| {
            let mut file = files.create_file(OsStr::new(name), 0o666).unwrap();
            file.write_all(name.as_bytes()).unwrap();
            drop(file);
            files.publish(
                OsStr::new(name),
                tree,
                Path::new(to),
                &root.join(to),
                overwrite,
                &mut renames,
            )
        };

        // A directory found missing is found once it is made.
        let missing = Path::new("a/b/file");
        assert_eq!(tree.lstat(missing).unwrap(), TreeEntry::Missing);
        assert_eq!(tree.lstat(missing).unwrap(), TreeEntry::Missing);
        let made = tree.create_dirs(Path::new("a/b")).unwrap();
        assert!(tree.created(&made));
        assert_eq!(
            tree.lstat(Path::new("a/b")).unwrap(),
            TreeEntry::Directory(made)
        );
        assert_eq!(
            publish(&mut tree, "0", "a/b/file", OverwritePolicy::Never).unwrap(),
            Some(root.join("a/b/file"))
        );
        assert_eq!(fs::read(root.join("a/b/file")).unwrap(), b"0");
        assert!(matches!(tree.lstat(missing).unwrap(), TreeEntry::Other(_)));
        assert!(matches!(
            publish(&mut tree, "1", "a/b/file", OverwritePolicy::Never),
            Err(crate::Error::Io(error)) if error.kind == std::io::ErrorKind::AlreadyExists
        ));
        assert_eq!(fs::read(root.join("a/b/file")).unwrap(), b"0");

        // A symlink planted mid-extraction where a directory goes is refused.
        std::os::unix::fs::symlink(&outside, root.join("c")).unwrap();
        assert!(matches!(
            publish(&mut tree, "2", "c/file", OverwritePolicy::Always),
            Err(crate::Error::UnsafePath(
                "unsafe archive path crosses symlink"
            ))
        ));
        // A directory already walked and then swapped for one is never
        // written through: the walk still holds the directory it opened.
        fs::rename(root.join("a/b"), scratch.join("moved")).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("a/b")).unwrap();
        publish(&mut tree, "3", "a/b/later", OverwritePolicy::Never).unwrap();
        assert_eq!(fs::read(scratch.join("moved/later")).unwrap(), b"3");
        assert_eq!(fs::read_dir(&outside).unwrap().count(), 0);

        // In a directory a walk made, only a real lstat looks.
        tree.create_dirs(Path::new("m/n")).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("m/n/planted")).unwrap();
        let planted = Path::new("m/n/planted");
        assert_eq!(tree.lstat(planted).unwrap(), TreeEntry::Symlink);
        assert_eq!(
            tree.lstat_unless_created(planted).unwrap(),
            TreeEntry::Missing
        );
        assert!(matches!(
            publish(&mut tree, "p", "m/n/planted", OverwritePolicy::Never),
            Err(crate::Error::Io(error)) if error.kind == std::io::ErrorKind::AlreadyExists
        ));
        fs::remove_file(root.join("m/n/planted")).unwrap();
        fs::create_dir(root.join("kept")).unwrap();
        fs::write(root.join("kept/file"), b"kept").unwrap();
        assert!(matches!(
            tree.lstat_unless_created(Path::new("kept/file")).unwrap(),
            TreeEntry::Other(_)
        ));
        assert_eq!(
            tree.lstat_unless_created(Path::new("link-free")).unwrap(),
            TreeEntry::Missing
        );
        assert_eq!(fs::read_dir(&outside).unwrap().count(), 0);
    }
}

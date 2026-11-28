//! Extracting an archive or a volume set into a directory.

use crate::extract_engine::{DirExtraction, DirMode, Outputs};
use crate::extraction_control::ExtractionErrorAction;
use crate::output_links::{extract_settled, SettledSource};
use crate::output_staging::OverwritePolicy;
use crate::{Archive, ArchiveFamily, ArchiveMember, ArchiveReadOptions, Error, ErrorKind, Result};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Options for [`Archive::extract_to_dir`] and [`extract_volumes_to_dir`].
///
/// The default refuses to overwrite, restores modification times and modes,
/// and reads with [`ArchiveReadOptions::default`].
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct ExtractDirOptions<'a> {
    /// The password, limits, cancellation, legacy name encoding, salvage and
    /// member error handler to extract with.
    ///
    /// [`ArchiveReadOptions::legacy_name_encoding`] decodes the names of
    /// RAR 1.3-4.x members not stored as Unicode. Unset, their bytes are used
    /// as they are stored.
    ///
    /// With [`ArchiveReadOptions::with_member_error_handler`], a member that
    /// fails is offered to the handler, and when it carries on, the member's
    /// output is dropped. A wrong password or an I/O error, such as an
    /// existing file `overwrite` refuses, still ends the call without
    /// reaching the handler. With [`ArchiveReadOptions::salvage`] as well, a
    /// member the handler carries on past keeps what was delivered for it,
    /// under its own name, unless it failed on its password.
    pub read: ArchiveReadOptions<'a>,
    /// What to do with a file already at a destination. [`OverwritePolicy::Never`]
    /// by default.
    pub overwrite: OverwritePolicy,
    /// Gives each file and directory the modification time the archive
    /// records, once extraction ends. On by default. Symbolic links keep
    /// their own times.
    pub restore_times: bool,
    /// Gives each file and directory the permissions the archive records, on
    /// Unix. On by default. A Unix mode is applied as stored; a DOS read-only
    /// file becomes `0o444`; anything else keeps the default permissions less
    /// the umask. Off, every file and directory keeps those defaults.
    /// Symbolic links keep their own modes.
    pub restore_modes: bool,
    /// Which symbolic links and junctions are made. [`SymlinkPolicy::Inside`] by default.
    pub symlinks: SymlinkPolicy,
}

/// Which symbolic links and junctions extraction makes, as RAR's `-ol` switches choose.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SymlinkPolicy {
    /// Those whose target stays inside the directory; the rest are left out and
    /// listed in [`ExtractedDir::skipped_links`]. RAR's default and `-ol`.
    #[default]
    Inside,
    /// Every one, as stored, wherever it leads, as `-ola` does. Extraction
    /// still never writes through a link: a later member stored under one this
    /// run made replaces it with a directory.
    All,
    /// None, as `-ol-` does; a hard link or file copy to one fails as its own member.
    Skip,
}

impl Default for ExtractDirOptions<'_> {
    fn default() -> Self {
        Self {
            read: ArchiveReadOptions::default(),
            overwrite: OverwritePolicy::Never,
            restore_times: true,
            restore_modes: true,
            symlinks: SymlinkPolicy::Inside,
        }
    }
}

impl<'a> ExtractDirOptions<'a> {
    /// The defaults: refuse to overwrite, restore times and modes, default read options.
    pub fn new() -> Self {
        Self::default()
    }

    /// Extracts with `read`. See [`Self::read`].
    #[must_use]
    pub fn with_read_options(mut self, read: ArchiveReadOptions<'a>) -> Self {
        self.read = read;
        self
    }

    /// Sets what to do with a file already at a destination.
    #[must_use]
    pub fn with_overwrite(mut self, overwrite: OverwritePolicy) -> Self {
        self.overwrite = overwrite;
        self
    }

    /// Sets whether modification times are restored.
    #[must_use]
    pub fn with_restore_times(mut self, restore_times: bool) -> Self {
        self.restore_times = restore_times;
        self
    }

    /// Sets whether file and directory modes are restored. See [`Self::restore_modes`].
    #[must_use]
    pub fn with_restore_modes(mut self, restore_modes: bool) -> Self {
        self.restore_modes = restore_modes;
        self
    }

    /// Sets which symbolic links and junctions are made. See [`Self::symlinks`].
    #[must_use]
    pub fn with_symlinks(mut self, symlinks: SymlinkPolicy) -> Self {
        self.symlinks = symlinks;
        self
    }
}

/// What [`Archive::extract_to_dir`] or [`extract_volumes_to_dir`] wrote.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ExtractedDir {
    /// Every file, directory and link written, in archive order, each under
    /// the directory extracted to. Under [`OverwritePolicy::Rename`] a file
    /// is listed where it landed.
    pub paths: Vec<PathBuf>,
    /// Symbolic links and junctions left out because they could lead outside
    /// the directory.
    pub skipped_links: Vec<SkippedLink>,
}

/// A link [`Archive::extract_to_dir`] left out because it could lead outside
/// the directory.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SkippedLink {
    /// The link member's name, as stored.
    pub name: Vec<u8>,
    /// Its target, as stored.
    pub target: Vec<u8>,
}

impl Archive {
    /// Extracts every member into `dir`, creating it if it is missing.
    ///
    /// ```no_run
    /// # fn main() -> rars::Result<()> {
    /// let archive = rars::ArchiveReader::read_path("game.rar")?;
    /// archive.extract_to_dir("game", &rars::ExtractDirOptions::default())?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// Every destination stays inside `dir`. A member whose name is absolute
    /// or climbs out with `..` is refused with [`Error::UnsafePath`], as is
    /// one whose path crosses a symbolic link already there. Directories are
    /// created as needed. Each file is written
    /// to private storage inside `dir` and moved to its destination once it
    /// verifies, so a member that fails leaves nothing at its destination; an
    /// existing hard link, FIFO or symbolic link there is never written
    /// through. Modes are restored as [`ExtractDirOptions::restore_modes`]
    /// says.
    ///
    /// Links are created: symbolic links and junctions as
    /// [`ExtractDirOptions::symlinks`] says, by default only when their target
    /// stays inside `dir`, else they are left out and listed in
    /// [`ExtractedDir::skipped_links`]. A hard link or file copy whose
    /// target was not extracted earlier fails as its own member. Where the
    /// platform can't create a symbolic link, the call fails.
    ///
    /// A member that fails ends the call with its error, leaving the members
    /// before it in place, unless `options.read` has a member error handler;
    /// see [`ExtractDirOptions::read`].
    pub fn extract_to_dir(
        &self,
        dir: impl AsRef<Path>,
        options: &ExtractDirOptions<'_>,
    ) -> Result<ExtractedDir> {
        extract_into(dir.as_ref(), self.family(), options, |read, outputs| {
            crate::extract_engine::extract_archive(self, read, None, outputs)
        })
    }
}

/// Extracts every member of a volume set into `dir`, as
/// [`Archive::extract_to_dir`] does. `volumes` are in order, starting with
/// the first.
///
/// ```no_run
/// # fn main() -> rars::Result<()> {
/// let volumes = ["game.part1.rar", "game.part2.rar"]
///     .into_iter()
///     .map(rars::ArchiveReader::read_path)
///     .collect::<rars::Result<Vec<_>>>()?;
/// rars::extract_volumes_to_dir(&volumes, "game", &rars::ExtractDirOptions::default())?;
/// # Ok(())
/// # }
/// ```
pub fn extract_volumes_to_dir(
    volumes: &[Archive],
    dir: impl AsRef<Path>,
    options: &ExtractDirOptions<'_>,
) -> Result<ExtractedDir> {
    let first = volumes
        .first()
        .ok_or(Error::InvalidHeader("volume set is empty"))?;
    extract_into(dir.as_ref(), first.family(), options, |read, outputs| {
        let lock = || outputs.lock().expect("outputs lock poisoned");
        extract_settled(
            SettledSource::Volumes(volumes),
            read,
            None,
            |meta| lock().open(meta),
            |meta, link| lock().link(meta, link),
            |_, outcome| lock().settle(outcome),
        )
    })
}

fn extract_into(
    dir: &Path,
    family: ArchiveFamily,
    options: &ExtractDirOptions<'_>,
    extract: impl FnOnce(ArchiveReadOptions<'_>, &Mutex<DirExtraction<'_>>) -> Result<()>,
) -> Result<ExtractedDir> {
    options.read.check_cancelled()?;
    let caller = options.read.member_errors;
    let handler = |member: &ArchiveMember, error: &Error| {
        let Some(caller) = caller else {
            return Ok(ExtractionErrorAction::Abort);
        };
        if matches!(error.kind(), ErrorKind::BadPassword | ErrorKind::Io) {
            return Ok(ExtractionErrorAction::Abort);
        }
        (caller.0)(member, error)
    };
    let read = match caller {
        Some(_) => options.read.with_member_error_handler(&handler),
        None => options.read,
    };
    let mode = DirMode {
        overwrite: options.overwrite,
        in_place: false,
        restore_times: options.restore_times,
        restore_modes: options.restore_modes,
        symlinks: options.symlinks,
        flatten: false,
        exists_hint: "; set ExtractDirOptions::overwrite to replace it or keep both",
    };
    let outputs = Mutex::new(DirExtraction::new(
        dir,
        family,
        read.legacy_name_encoding,
        mode,
    ));
    let result = extract(read, &outputs);
    outputs
        .into_inner()
        .expect("outputs lock poisoned")
        .finish(result)
}

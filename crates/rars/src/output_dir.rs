//! Extraction into a directory: the engine behind [`crate::Archive::extract_to_dir`]
//! and the Python binding's `extractall`.
//! Shared with the Python binding; not part of the stable API.

use crate::extract_dir::{ExtractedDir, SkippedLink};
use crate::output_links::{create_link_output, link_source_path};
use crate::output_staging::{
    failed_entry_name, publish_verified_output, refused_output, ExtractionStaging, OverwritePolicy,
};
use crate::output_tree::{FileDir, HeldFile, OutputTree, TreeEntry};
use crate::ExtractedLink;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

/// How [`DirOutputs`] writes.
#[derive(Debug, Clone, Copy)]
pub struct DirMode {
    pub overwrite: OverwritePolicy,
    /// Writes each destination itself instead of staging it.
    pub in_place: bool,
    pub restore_times: bool,
    /// Writes every file straight into the directory under its base name.
    pub flatten: bool,
    /// Follows "`<path>` already exists" when `overwrite` is `Never` refuses a file.
    pub exists_hint: &'static str,
}

/// Stages each file and publishes it once verified, so a hard link or FIFO at
/// the destination is never written through, unless writing in place.
pub struct DirOutputs<'a> {
    out_dir: &'a Path,
    family: crate::ArchiveFamily,
    encoding: Option<crate::filename::LegacyNameEncoding>,
    overwrite: OverwritePolicy,
    in_place: bool,
    flatten: bool,
    exists_hint: &'static str,
    flat_names: crate::output_staging::FlatNames,
    renames: crate::output_staging::RenameCounters,
    /// Destinations taken under `Rename`, so a repeated stored path fails as in the CLI.
    rename_claims: HashSet<PathBuf>,
    times: Option<crate::output_times::OutputTimes>,
    staging: Option<ExtractionStaging>,
    staged: usize,
    pending: Option<PendingOutput>,
    published: Vec<PathBuf>,
    /// Where each output went, by its stored path, for hard links and copies.
    created: HashMap<PathBuf, PathBuf>,
    skipped_links: Vec<SkippedLink>,
    /// Members a member error handler went past, whose pending output is dropped.
    failed: Option<&'a Mutex<Vec<Vec<u8>>>>,
    /// The output directory walked by descriptor, where the platform allows,
    /// once it exists. Each directory is opened once without following a
    /// symlink, and files are created and published relative to it.
    out_tree: Option<OutputTree>,
    /// Where files stage by descriptor in the staging storage, and its path.
    staged_files: Option<(FileDir, PathBuf)>,
}

/// Where staged files go in a staging storage walked by descriptor. Links
/// stage beside it under their numbers.
const STAGED_FILES: &str = "files";

struct PendingOutput {
    /// None when the member is written in place.
    staged: Option<PathBuf>,
    /// Staged by descriptor: the directory it is in and its name there.
    staged_at: Option<(FileDir, std::ffi::OsString)>,
    /// Written in place by descriptor: the file, once the library is done writing it.
    held: Option<Arc<OnceLock<fs::File>>>,
    stored: PathBuf,
    destination: PathBuf,
    meta: crate::ExtractedEntryMeta,
    /// A legacy symlink's target, buffered until verified.
    link_target: Option<Arc<Mutex<Vec<u8>>>>,
}

struct SharedBuffer(Arc<Mutex<Vec<u8>>>);

impl Write for SharedBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .expect("link target lock poisoned")
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> DirOutputs<'a> {
    /// Outputs under `out_dir` for an archive of `family`, decoding legacy
    /// names with `encoding`. A member named in `failed` when its output
    /// would be published is dropped instead.
    pub fn new(
        out_dir: &'a Path,
        family: crate::ArchiveFamily,
        encoding: Option<crate::filename::LegacyNameEncoding>,
        mode: DirMode,
        failed: Option<&'a Mutex<Vec<Vec<u8>>>>,
    ) -> Self {
        Self {
            out_dir,
            family,
            encoding,
            overwrite: mode.overwrite,
            in_place: mode.in_place,
            flatten: mode.flatten,
            exists_hint: mode.exists_hint,
            flat_names: Default::default(),
            renames: Default::default(),
            rename_claims: HashSet::new(),
            times: mode
                .restore_times
                .then(crate::output_times::OutputTimes::new),
            staging: None,
            staged: 0,
            pending: None,
            published: Vec::new(),
            created: HashMap::new(),
            skipped_links: Vec::new(),
            failed,
            out_tree: None,
            staged_files: None,
        }
    }

    /// The output directory walked by descriptor, opened once it exists, or
    /// made first if `create`. `None` where the platform has no such walk.
    fn tree(&mut self, create: bool) -> crate::Result<Option<&mut OutputTree>> {
        if self.out_tree.is_none() && crate::output_tree::AVAILABLE {
            if create {
                fs::create_dir_all(self.out_dir)?;
            }
            self.out_tree = OutputTree::open(self.out_dir)?;
        }
        Ok(self.out_tree.as_mut())
    }

    /// Drops the walks' open directories, after a change made by path.
    fn forget_walks(&mut self) {
        if let Some(tree) = &mut self.out_tree {
            tree.forget();
        }
    }

    /// Stored path for link lookups, and destination, which flattening
    /// reduces to the base name. Refuses a symlink on the way to it or at it.
    /// With the output directory walked by descriptor, also what is there now.
    fn destination(
        &mut self,
        meta: &crate::ExtractedEntryMeta,
    ) -> crate::Result<(PathBuf, PathBuf, Option<TreeEntry>)> {
        let refuse = |error| refused_output(error, &meta.name);
        let (stored, relative) =
            output_names(meta, self.family, self.encoding, self.flatten).map_err(refuse)?;
        let path = self.out_dir.join(&relative);
        if let Some(tree) = self.tree(false).map_err(refuse)? {
            return match tree.lstat(&relative).map_err(refuse)? {
                TreeEntry::Symlink => Err(refuse(crate::Error::UnsafePath(
                    "unsafe archive path crosses symlink",
                ))),
                entry => Ok((stored, path, Some(entry))),
            };
        }
        crate::filename::checked_output_path(self.out_dir, &relative).map_err(refuse)?;
        if let Some(staging) = &self.staging {
            staging.reject_alias(&path).map_err(refuse)?;
        }
        Ok((stored, path, None))
    }

    /// The time to give a published file, if any.
    fn modified_time(&self, meta: &crate::ExtractedEntryMeta) -> Option<std::time::SystemTime> {
        self.times.as_ref()?;
        meta.modified
            .and_then(|time| std::time::SystemTime::try_from(time).ok())
    }

    fn claim(&mut self, destination: &Path, meta: &crate::ExtractedEntryMeta) -> crate::Result<()> {
        if self.flatten {
            let relative = destination
                .strip_prefix(self.out_dir)
                .expect("checked output path is under the output directory");
            return self
                .flat_names
                .claim(relative, &meta.name, self.overwrite)
                .map_err(|error| refused_output(error, &meta.name));
        }
        if self.overwrite == OverwritePolicy::Rename
            && !meta.is_directory
            && !self.rename_claims.insert(destination.to_path_buf())
        {
            return Err(crate::Error::InvalidHeader(
                "multiple archive entries map to the same output path",
            ));
        }
        if self.encoding.is_some() && self.published.iter().any(|path| path == destination) {
            return Err(crate::Error::InvalidArgument(
                "multiple entries map to the same decoded output path",
            ));
        }
        Ok(())
    }

    /// What `<destination> already exists` says when `Never` refuses it.
    fn already_exists(&self, destination: &Path) -> io::Error {
        io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "{} already exists{}",
                destination.display(),
                self.exists_hint
            ),
        )
    }

    /// Opens a file or directory member's output. The library has verified
    /// the previous member by the time it asks for another output.
    pub fn open(&mut self, meta: &crate::ExtractedEntryMeta) -> crate::Result<Box<dyn Write>> {
        self.publish_pending()?;
        if self.flatten && meta.is_directory {
            return Ok(Box::new(io::sink()));
        }
        let (stored, destination, existing) = self.destination(meta)?;
        self.claim(&destination, meta)?;
        if meta.is_directory {
            self.create_directory(&destination, existing.as_ref(), &meta.name)?;
            self.record_published(stored, destination, meta, true);
            return Ok(Box::new(io::sink()));
        }
        let exists = match &existing {
            Some(entry) => *entry != TreeEntry::Missing,
            None => fs::symlink_metadata(&destination).is_ok(),
        };
        if self.overwrite == OverwritePolicy::Never && exists {
            return Err(self.already_exists(&destination).into());
        }
        if self.in_place {
            return self.open_in_place(stored, destination, meta);
        }
        self.open_staged(stored, destination, meta)
    }

    /// Makes a directory member, and any missing parents.
    fn create_directory(
        &mut self,
        destination: &Path,
        existing: Option<&TreeEntry>,
        name: &[u8],
    ) -> crate::Result<()> {
        let relative = destination
            .strip_prefix(self.out_dir)
            .expect("checked output path is under the output directory");
        if matches!(existing, Some(TreeEntry::Other(_))) {
            // What `create_dir_all` says of a file in the way.
            return Err(file_in_the_way().into());
        }
        match self.tree(true)? {
            Some(tree) => {
                tree.create_dirs(relative)
                    .map_err(|error| like_create_dir_all(refused_walk(error, name), destination))?;
            }
            None => fs::create_dir_all(destination)?,
        }
        Ok(())
    }

    /// Opens a member at its destination by the overwrite policy, never
    /// following a symlink and never writing through a hard link or
    /// anything but a regular file.
    fn open_in_place(
        &mut self,
        stored: PathBuf,
        destination: PathBuf,
        meta: &crate::ExtractedEntryMeta,
    ) -> crate::Result<Box<dyn Write>> {
        let parent = destination
            .parent()
            .expect("checked output path has a file name")
            .to_path_buf();
        self.tree(true)?;
        let (destination, writer, held): (_, Box<dyn Write>, _) = match &mut self.out_tree {
            Some(tree) => {
                let relative = destination
                    .strip_prefix(self.out_dir)
                    .expect("checked output path is under the output directory");
                let (dir, _) = tree.parent_dir(relative).map_err(|error| {
                    like_create_dir_all(refused_walk(error, &meta.name), &parent)
                })?;
                let name = relative.file_name().expect("output path has a name");
                let (destination, file) = match self.overwrite {
                    OverwritePolicy::Never => {
                        let file = dir.create_file(name, 0o666)?;
                        (destination, file)
                    }
                    OverwritePolicy::Rename => {
                        dir.create_numbered(&destination, 0o666, &mut self.renames)?
                    }
                    OverwritePolicy::Always => {
                        let opened = dir.open_in_place(name, 0o666)?;
                        if opened.len > 0 {
                            opened.file.set_len(0)?;
                        }
                        (destination, opened.file)
                    }
                };
                let (writer, held) = HeldFile::new(file);
                (destination, Box::new(writer), Some(held))
            }
            None => {
                fs::create_dir_all(&parent)?;
                // Creating the parents may have raced a symlink into place.
                let (_, destination, _) = self.destination(meta)?;
                let (destination, file) = crate::output_staging::open_in_place(
                    &destination,
                    self.overwrite,
                    &mut self.renames,
                )?;
                (destination, Box::new(file), None)
            }
        };
        self.pending = Some(PendingOutput {
            staged: None,
            staged_at: None,
            held,
            stored,
            destination,
            meta: meta.clone(),
            link_target: None,
        });
        Ok(writer)
    }

    /// The staging storage, made on first use. Where the output directory is
    /// walked by descriptor, so is the storage, and the walks refuse it.
    fn staging(&mut self) -> crate::Result<&ExtractionStaging> {
        if self.staging.is_none() {
            let staging = ExtractionStaging::new(self.out_dir)?;
            if let Some(tree) = self.tree(false)? {
                if let Some(mut storage) = OutputTree::open(&staging.root)? {
                    tree.forbid(storage.identity());
                    let files = storage.file_dir(Path::new(STAGED_FILES))?;
                    self.staged_files = Some((files, staging.root.join(STAGED_FILES)));
                }
            }
            self.staging = Some(staging);
        }
        Ok(self.staging.as_ref().expect("made above"))
    }

    /// Stages a member's file, to publish once it verifies.
    fn open_staged(
        &mut self,
        stored: PathBuf,
        destination: PathBuf,
        meta: &crate::ExtractedEntryMeta,
    ) -> crate::Result<Box<dyn Write>> {
        self.staging()?;
        let staging = self.staging.as_ref().expect("made above");
        if self.staged_files.is_none() {
            staging
                .reject_alias(&destination)
                .map_err(|error| refused_output(error, &meta.name))?;
        } else if destination.starts_with(&staging.root) {
            // Walked before the storage was there to refuse.
            return Err(refused_output(
                crate::Error::InvalidHeader("archive path conflicts with extraction storage"),
                &meta.name,
            ));
        }
        let index = self.staged.to_string();
        let (staged, staged_at, file) = match &self.staged_files {
            Some((dir, root)) => {
                let name = std::ffi::OsString::from(index);
                let file = dir.create_file(&name, 0o666)?;
                (root.join(&name), Some((dir.clone(), name)), file)
            }
            None => {
                let staged = staging.root.join(index);
                let file = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&staged)?;
                (staged, None, file)
            }
        };
        self.staged += 1;
        self.pending = Some(PendingOutput {
            staged: Some(staged),
            staged_at,
            held: None,
            stored,
            destination,
            meta: meta.clone(),
            link_target: None,
        });
        Ok(Box::new(file))
    }

    /// Publishes the member written last, once it has verified.
    pub fn publish_pending(&mut self) -> crate::Result<()> {
        let Some(pending) = self.pending.take() else {
            return Ok(());
        };
        // The library reports a failed member before it asks for the next output.
        let failed = self.failed.is_some_and(|failed| {
            let mut failed = failed.lock().expect("failed members lock poisoned");
            let gone_past = failed.contains(&pending.meta.name);
            failed.clear();
            gone_past
        });
        if failed {
            if let Some(staged) = &pending.staged {
                let _ = fs::remove_file(staged);
            }
            return Ok(());
        }
        if let Some(target) = pending.link_target {
            let target = std::mem::take(&mut *target.lock().expect("link target lock poisoned"));
            crate::output_links::check_legacy_symlink_target(
                &pending.meta.name,
                target.len() as u64,
                Some(&target),
            )?;
            return self.link(
                &pending.meta,
                ExtractedLink::Symlink {
                    target: &target,
                    directory: false,
                },
            );
        }
        let Some(staged) = &pending.staged else {
            // Written in place: by descriptor, its time goes on through its own.
            let later = match (&pending.held, self.modified_time(&pending.meta)) {
                (Some(held), Some(modified)) => !held
                    .get()
                    .is_some_and(|file| file.set_modified(modified).is_ok()),
                _ => true,
            };
            self.record_published(pending.stored, pending.destination, &pending.meta, later);
            return Ok(());
        };
        if let Some((dir, name)) = &pending.staged_at {
            if let Some(published) = self.publish_by_descriptor(&pending, dir, name)? {
                self.record_published(pending.stored, published.0, &pending.meta, published.1);
                return Ok(());
            }
            // The filesystem can't rename it into place: publish it by path.
            self.forget_walks();
        }
        fs::create_dir_all(
            pending
                .destination
                .parent()
                .expect("checked output path has a file name"),
        )?;
        // Creating the parents may have raced a symlink into place.
        let (_, destination, _) = self.destination(&pending.meta)?;
        let destination = publish_verified_output(
            staged,
            &destination,
            self.overwrite,
            None,
            &mut self.renames,
        )?;
        self.record_published(pending.stored, destination, &pending.meta, true);
        Ok(())
    }

    /// Publishes a file staged by descriptor, renaming it from the storage
    /// into the output directory's walked descriptors after giving it its
    /// time. Returns where it landed and whether its time still needs
    /// setting, or `None` when the filesystem can't rename it into place.
    fn publish_by_descriptor(
        &mut self,
        pending: &PendingOutput,
        dir: &FileDir,
        name: &std::ffi::OsStr,
    ) -> crate::Result<Option<(PathBuf, bool)>> {
        let later = match self.modified_time(&pending.meta) {
            Some(modified) => dir.set_metadata(name, Some(modified), None).is_err(),
            None => true,
        };
        let relative = pending
            .destination
            .strip_prefix(self.out_dir)
            .expect("checked output path is under the output directory");
        let parent = pending
            .destination
            .parent()
            .expect("checked output path has a file name");
        let tree = self
            .out_tree
            .as_mut()
            .expect("files stage by descriptor only beside an output tree");
        let published = dir
            .publish(
                name,
                tree,
                relative,
                &pending.destination,
                self.overwrite,
                &mut self.renames,
            )
            .map_err(|error| {
                like_create_dir_all(refused_walk(error, &pending.meta.name), parent)
            })?;
        Ok(published.map(|published| (published, later)))
    }

    /// Buffers a legacy symlink's target; the link is made once the target is verified.
    pub fn open_legacy_link(
        &mut self,
        meta: &crate::ExtractedEntryMeta,
    ) -> crate::Result<Box<dyn Write>> {
        self.publish_pending()?;
        let target = Arc::new(Mutex::new(Vec::new()));
        self.pending = Some(PendingOutput {
            staged: None,
            staged_at: None,
            held: None,
            stored: PathBuf::new(),
            destination: PathBuf::new(),
            meta: meta.clone(),
            link_target: Some(Arc::clone(&target)),
        });
        Ok(Box::new(SharedBuffer(target)))
    }

    /// Creates a link member, or records it as skipped when it could lead
    /// outside the directory.
    pub fn link(
        &mut self,
        meta: &crate::ExtractedEntryMeta,
        link: ExtractedLink<'_>,
    ) -> crate::Result<()> {
        self.publish_pending()?;
        let (stored, destination, existing) = self.destination(meta)?;
        let relative = destination
            .strip_prefix(self.out_dir)
            .expect("checked output path is under the output directory")
            .to_path_buf();
        let Some(target) = crate::output_links::link_target(
            self.out_dir,
            &relative,
            meta,
            link,
            self.family,
            self.flatten,
        )?
        else {
            self.skipped_links.push(SkippedLink {
                name: meta.name.clone(),
                target: link.target().to_vec(),
            });
            return Ok(());
        };
        self.claim(&destination, meta)?;
        if self.in_place {
            let created = create_link_output(
                self.out_dir,
                &relative,
                &target,
                link,
                self.overwrite,
                &self.created,
                &mut self.renames,
            );
            // Made by path, which can remove a directory the walks hold.
            self.forget_walks();
            let (path, file) = created?;
            self.record_published(stored, path, meta, file);
            return Ok(());
        }
        let exists = match &existing {
            Some(entry) => *entry != TreeEntry::Missing,
            None => fs::symlink_metadata(&destination).is_ok(),
        };
        if self.overwrite == OverwritePolicy::Never && exists {
            return Err(self.already_exists(&destination).into());
        }
        let root = self.staging()?.root.clone();
        let (staged, file) = create_link_output(
            &root,
            Path::new(&self.staged.to_string()),
            &target,
            link,
            OverwritePolicy::Never,
            &self.created,
            &mut self.renames,
        )?;
        self.staged += 1;
        let source = match link {
            ExtractedLink::HardLink { .. } => {
                Some(link_source_path(&target, &self.created)?.to_path_buf())
            }
            _ => None,
        };
        fs::create_dir_all(
            destination
                .parent()
                .expect("checked output path has a file name"),
        )?;
        // Made by path: walk afresh.
        self.forget_walks();
        // Creating the parents may have raced a symlink into place.
        let (_, destination, _) = self.destination(meta)?;
        if self.overwrite == OverwritePolicy::Always
            && fs::symlink_metadata(&destination).is_ok_and(|metadata| metadata.is_dir())
        {
            fs::remove_dir(&destination)?;
        }
        let published = publish_verified_output(
            &staged,
            &destination,
            self.overwrite,
            source.as_deref(),
            &mut self.renames,
        );
        // Replacing a directory removes it, wherever the walks hold it.
        self.forget_walks();
        self.record_published(stored, published?, meta, file);
        Ok(())
    }

    /// Symlinks keep their own times: setting them would follow the link.
    fn record_published(
        &mut self,
        stored: PathBuf,
        path: PathBuf,
        meta: &crate::ExtractedEntryMeta,
        restore_times: bool,
    ) {
        if let (Some(times), true) = (&mut self.times, restore_times) {
            times.opened(path.clone(), meta);
            times.finish();
        }
        self.created.insert(stored, path.clone());
        self.published.push(path);
    }

    /// A member still in flight when extraction failed never reaches its destination.
    pub fn finish(mut self, result: crate::Result<()>) -> crate::Result<ExtractedDir> {
        let published = match result {
            Ok(()) => self.publish_pending(),
            Err(error) => {
                let verified = matches!(
                    (failed_entry_name(&error), &self.pending),
                    (Some(failed), Some(pending)) if failed != pending.meta.name.as_slice()
                );
                if verified {
                    // The extraction's own error wins over a failure to publish.
                    let _ = self.publish_pending();
                }
                Err(error)
            }
        };
        let restored = match &self.times {
            Some(times) => times.restore(),
            None => Ok(()),
        };
        published?;
        restored?;
        let mut paths = std::mem::take(&mut self.published);
        if self.flatten && self.overwrite == OverwritePolicy::Always {
            // A member that replaced an earlier one is listed once, where it last landed.
            let mut seen = HashSet::new();
            paths.reverse();
            paths.retain(|path| seen.insert(path.clone()));
            paths.reverse();
        }
        Ok(ExtractedDir {
            paths,
            skipped_links: std::mem::take(&mut self.skipped_links),
        })
    }
}

/// The member's stored relative path, and where it goes relative to the output directory.
fn output_names(
    meta: &crate::ExtractedEntryMeta,
    family: crate::ArchiveFamily,
    encoding: Option<crate::filename::LegacyNameEncoding>,
    flatten: bool,
) -> crate::Result<(PathBuf, PathBuf)> {
    // A conservative name preflight (including legacy backslash traversal)
    // before the host-aware destination conversion.
    crate::validate_entry_name(meta.name.clone())?;
    let rar50 = family == crate::ArchiveFamily::Rar50Plus;
    let name = if rar50 {
        crate::output_links::rar50_native_name(
            &meta.name,
            meta.attr_source == crate::AttrSource::Unix,
        )
    } else {
        crate::filename::decoded_name(&meta.name, meta.name_is_unicode, encoding)?.into_owned()
    };
    let stored = crate::filename::relative_path(&name, !rar50)?;
    let relative = if flatten {
        crate::output_staging::flat_relative(&stored)
    } else {
        stored.clone()
    };
    Ok((stored, relative))
}

/// Names the member a walk refused, as the checks by path did. Errors from
/// the filesystem itself pass through as they would from `create_dir_all`.
fn refused_walk(error: crate::Error, name: &[u8]) -> crate::Error {
    match error {
        crate::Error::Io(_) => error,
        error => refused_output(error, name),
    }
}

/// What `create_dir_all` says of a file where a directory goes.
fn file_in_the_way() -> io::Error {
    #[cfg(unix)]
    return io::Error::from_raw_os_error(libc::EEXIST);
    #[cfg(not(unix))]
    return io::ErrorKind::AlreadyExists.into();
}

/// `create_dir_all` reports a file where `directory` goes as `EEXIST`. A walk
/// by descriptor finds it can't open it as a directory, `ENOTDIR`, so it is
/// reported as `create_dir_all` would.
fn like_create_dir_all(error: crate::Error, directory: &Path) -> crate::Error {
    #[cfg(unix)]
    {
        let not_a_directory = matches!(
            error.root_cause(),
            crate::Error::Io(io) if io
                .source()
                .downcast_ref::<io::Error>()
                .and_then(io::Error::raw_os_error)
                == Some(libc::ENOTDIR)
        );
        if not_a_directory
            && fs::symlink_metadata(directory).is_ok_and(|metadata| !metadata.is_dir())
        {
            return file_in_the_way().into();
        }
    }
    #[cfg(not(unix))]
    let _ = directory;
    error
}

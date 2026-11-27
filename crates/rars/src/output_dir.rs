//! Extraction into a directory: the engine behind [`crate::Archive::extract_to_dir`]
//! and the Python binding's `extractall`.
//! Shared with the Python binding; not part of the stable API.

use crate::extract_dir::{ExtractedDir, SkippedLink};
use crate::in_flight::InFlight;
use crate::output_links::{create_link_output, link_source_path, MadeLink};
use crate::output_modes::{early_mode, set_file_mode, CreatedModes, PathModes};
use crate::output_staging::{
    failed_entry_name, publish_verified_output, refused_output, ExtractionStaging, OverwritePolicy,
};
use crate::output_tree::{DeferredFile, FileDir, HeldFile, OutputTree, TreeEntry};
use crate::publish_queue::{PublishQueue, PublishStep};
use crate::ExtractedLink;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::SystemTime;

/// How [`DirOutputs`] writes.
#[derive(Debug, Clone, Copy)]
pub struct DirMode {
    pub overwrite: OverwritePolicy,
    /// Writes each destination itself instead of staging it.
    pub in_place: bool,
    pub restore_times: bool,
    pub restore_modes: bool,
    /// Writes every file straight into the directory under its base name.
    pub flatten: bool,
    /// Follows "`<path>` already exists" when `overwrite` is `Never` refuses a file.
    pub exists_hint: &'static str,
}

/// Stages each file and publishes it once verified, so a hard link or FIFO at
/// the destination is never written through, unless writing in place.
pub struct DirOutputs<'a> {
    out_dir: &'a Path,
    encoding: Option<crate::filename::LegacyNameEncoding>,
    overwrite: OverwritePolicy,
    in_place: bool,
    flatten: bool,
    restore_times: bool,
    restore_modes: bool,
    /// Whether files created with a mode keep it, learnt once per mode.
    created_modes: CreatedModes,
    exists_hint: &'static str,
    flat_names: crate::output_staging::FlatNames,
    /// Destinations taken under `Rename`, so a repeated stored path fails as in the CLI.
    rename_claims: HashSet<PathBuf>,
    staged: usize,
    storage: Option<Storage>,
    pending: Option<PendingOutput>,
    /// Members opened by [`Self::open_settled`] and not yet settled, oldest first.
    unsettled: VecDeque<Unsettled>,
    /// Where unsettled members go.
    unsettled_paths: InFlight,
    skipped_links: Vec<SkippedLink>,
    /// Members a member error handler went past, whose pending output is dropped.
    failed: Option<&'a Mutex<Vec<Vec<u8>>>>,
    queue: PublishQueue<Publishing>,
    /// A failure to publish was handed on: the run going on publishes what is held behind it.
    failure_given: bool,
}

/// Where files stage, once the storage is made.
#[derive(Clone)]
struct Storage {
    root: PathBuf,
    /// Staged by descriptor: this directory of the storage, and its path.
    files: Option<(FileDir, PathBuf)>,
}

/// What publishing changes, and opening reads through the queue's lock.
struct Publishing {
    out_dir: PathBuf,
    family: crate::ArchiveFamily,
    encoding: Option<crate::filename::LegacyNameEncoding>,
    overwrite: OverwritePolicy,
    flatten: bool,
    renames: crate::output_staging::RenameCounters,
    times: Option<crate::output_times::OutputTimes>,
    /// Modes no descriptor could set, set by path at the end.
    modes: Option<PathModes>,
    staging: Option<ExtractionStaging>,
    /// Where files stage, once [`Self::staging`] is made.
    storage: Option<Storage>,
    /// The output directory walked by descriptor, where the platform allows,
    /// once it exists. Each directory is opened once without following a
    /// symlink, and files are created and published relative to it.
    out_tree: Option<OutputTree>,
    published: Vec<PathBuf>,
    /// Where each output went, by its stored path, for hard links and copies.
    created: HashMap<PathBuf, PathBuf>,
    /// Where outputs queued and not yet published go.
    queued: InFlight,
}

/// Where staged files go in a staging storage walked by descriptor. Links
/// stage beside it under their numbers.
const STAGED_FILES: &str = "files";

struct PendingOutput {
    /// None when the member is written in place.
    staged: Option<PathBuf>,
    /// Staged by descriptor: the directory it is in and its name there.
    staged_at: Option<(FileDir, std::ffi::OsString)>,
    /// What the staged file did as it closed.
    closed: Option<Arc<CloseOutcome>>,
    /// Written in place by descriptor: the file, once the library is done writing it.
    held: Option<Arc<OnceLock<fs::File>>>,
    stored: PathBuf,
    destination: PathBuf,
    meta: crate::ExtractedEntryMeta,
    /// A legacy symlink's target, buffered until verified.
    link_target: Option<Arc<Mutex<Vec<u8>>>>,
}

enum Unsettled {
    Refused,
    /// Made once it settles, so a file before it in the archive is published first.
    Directory {
        meta: crate::ExtractedEntryMeta,
        destination: PathBuf,
    },
    Output {
        pending: PendingOutput,
        /// Looked at again as it settles: a member before it can change what is at its destination.
        recheck: bool,
    },
}

enum Job {
    Output(PendingOutput),
    Directory {
        meta: crate::ExtractedEntryMeta,
        destination: PathBuf,
    },
}

impl Job {
    fn destination(&self) -> (&Path, bool) {
        match self {
            Self::Output(pending) => (&pending.destination, false),
            Self::Directory { destination, .. } => (destination, true),
        }
    }
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

/// Takes its member's time and mode as it closes, so the publish needs no call by name.
struct StagedFile {
    file: DeferredFile,
    modified: Option<SystemTime>,
    /// The mode it was created with, which it must end with.
    mode: Option<u32>,
    created_modes: CreatedModes,
    closed: Arc<CloseOutcome>,
}

#[derive(Default)]
struct CloseOutcome {
    /// An empty member nothing wrote is created as it closes, which can fail unheard.
    created: AtomicBool,
    time_set: AtomicBool,
    mode_set: AtomicBool,
}

impl Write for StagedFile {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.file.write(bytes)
    }

    fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.file.write_all(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

impl Drop for StagedFile {
    fn drop(&mut self) {
        let Ok(file) = self.file.file() else {
            return;
        };
        self.closed.created.store(true, Ordering::Release);
        if let Some(modified) = self.modified {
            if file.set_modified(modified).is_ok() {
                self.closed.time_set.store(true, Ordering::Release);
            }
        }
        if let Some(mode) = self.mode {
            if self.created_modes.apply(file, mode).is_ok() {
                self.closed.mode_set.store(true, Ordering::Release);
            }
        }
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
        let mut queue = PublishQueue::new(Publishing {
            out_dir: out_dir.to_path_buf(),
            family,
            encoding,
            overwrite: mode.overwrite,
            flatten: mode.flatten,
            renames: Default::default(),
            times: mode
                .restore_times
                .then(crate::output_times::OutputTimes::new),
            modes: mode.restore_modes.then(PathModes::default),
            staging: None,
            storage: None,
            out_tree: None,
            published: Vec::new(),
            created: HashMap::new(),
            queued: InFlight::default(),
        });
        // In place, opening writes the destination; flattened, it claims names publishing keeps.
        queue.publish_on_thread(!mode.in_place && !mode.flatten);
        Self {
            out_dir,
            encoding,
            overwrite: mode.overwrite,
            in_place: mode.in_place,
            flatten: mode.flatten,
            restore_times: mode.restore_times,
            restore_modes: mode.restore_modes,
            created_modes: CreatedModes::default(),
            exists_hint: mode.exists_hint,
            flat_names: Default::default(),
            rename_claims: HashSet::new(),
            staged: 0,
            storage: None,
            pending: None,
            unsettled: VecDeque::new(),
            unsettled_paths: InFlight::default(),
            skipped_links: Vec::new(),
            failed,
            queue,
            failure_given: false,
        }
    }

    /// For code the run calls out to, which can look at the output directory.
    pub fn publish_waiter(&self) -> impl Fn() + Send + Sync + 'static {
        self.queue.waiter()
    }

    /// The run went on past the failure handed on: outputs held behind it publish.
    fn go_on(&mut self) {
        if std::mem::take(&mut self.failure_given) {
            self.queue.resume();
        }
    }

    /// The first failure to publish an output queued earlier.
    fn publish_failure(&mut self) -> crate::Result<()> {
        match self.queue.take_failure() {
            Some(failure) => {
                self.failure_given = true;
                Err(failure)
            }
            None => Ok(()),
        }
    }

    fn submit(&mut self, job: Job) {
        let (destination, directory) = job.destination();
        self.queue.state().note_queued(destination, directory);
        self.queue.submit(job);
    }

    /// Stored path for link lookups, destination, and what is there now, once
    /// no output queued ahead of it can change what opening finds.
    fn destination(
        &mut self,
        meta: &crate::ExtractedEntryMeta,
    ) -> crate::Result<(PathBuf, PathBuf, Option<TreeEntry>)> {
        {
            let mut state = self.queue.state();
            let found = state.destination(meta)?;
            if !state.waits_for_queued(&found.1, meta.is_directory) {
                return Ok(found);
            }
        }
        self.queue.wait();
        // A failure held what is queued behind it: what opening would find isn't settled.
        self.publish_failure()?;
        self.queue.state().destination(meta)
    }

    /// The time to give a published file, if any.
    fn modified_time(&self, meta: &crate::ExtractedEntryMeta) -> Option<SystemTime> {
        if !self.restore_times {
            return None;
        }
        meta.modified
            .and_then(|time| SystemTime::try_from(time).ok())
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
        if self.encoding.is_some() {
            let repeated = || {
                Err(crate::Error::InvalidArgument(
                    "multiple entries map to the same decoded output path",
                ))
            };
            if self.unsettled_paths.holds(self.relative(destination)) {
                return repeated();
            }
            if self.queue.state().is_queued(destination) {
                self.queue.wait();
            }
            if self.queue.state().is_published(destination) {
                return repeated();
            }
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
        self.go_on();
        self.publish_previous()?;
        if self.flatten && meta.is_directory {
            return Ok(Box::new(io::sink()));
        }
        let (stored, destination, existing) = self.destination(meta)?;
        self.claim(&destination, meta)?;
        if meta.is_directory {
            self.submit(Job::Directory {
                meta: meta.clone(),
                destination,
            });
            self.publish_failure()?;
            return Ok(Box::new(io::sink()));
        }
        if self.overwrite == OverwritePolicy::Never && exists(&destination, existing.as_ref()) {
            return Err(self.already_exists(&destination).into());
        }
        if self.in_place {
            return self.open_in_place(stored, destination, meta);
        }
        Ok(self.open_staged(stored, destination, meta)?)
    }

    /// For [`Self::settle`]: opening can't read what members still unsettled will publish, so writing in place or flattened can't use it.
    pub fn open_settled(
        &mut self,
        meta: &crate::ExtractedEntryMeta,
    ) -> crate::Result<Box<dyn Write + Send>> {
        debug_assert!(!self.in_place && !self.flatten);
        self.go_on();
        let opened = self
            .publish_failure()
            .and_then(|()| self.open_unsettled(meta));
        let (writer, unsettled) = match opened {
            Ok(opened) => opened,
            Err(error) => {
                self.unsettled.push_back(Unsettled::Refused);
                return Err(error);
            }
        };
        let destination = match &unsettled {
            Unsettled::Output { pending, .. } => Some((&pending.destination, false)),
            Unsettled::Directory { destination, .. } => Some((destination, true)),
            Unsettled::Refused => None,
        };
        if let Some((destination, directory)) = destination {
            let relative = self.relative(destination);
            self.unsettled_paths.add(relative, directory);
        }
        self.unsettled.push_back(unsettled);
        Ok(writer)
    }

    fn open_unsettled(
        &mut self,
        meta: &crate::ExtractedEntryMeta,
    ) -> crate::Result<(Box<dyn Write + Send>, Unsettled)> {
        let (stored, destination, existing) = self.destination(meta)?;
        self.claim(&destination, meta)?;
        if meta.is_directory {
            let unsettled = Unsettled::Directory {
                meta: meta.clone(),
                destination,
            };
            return Ok((Box::new(io::sink()), unsettled));
        }
        if self.overwrite == OverwritePolicy::Never && exists(&destination, existing.as_ref()) {
            return Err(self.already_exists(&destination).into());
        }
        let recheck = self
            .unsettled_paths
            .changes(self.relative(&destination), false);
        let writer = self.open_staged(stored, destination, meta)?;
        let pending = self.pending.take().expect("staged above");
        Ok((writer, Unsettled::Output { pending, recheck }))
    }

    /// Queues or drops the oldest member from [`Self::open_settled`]. An error
    /// is that member's own, or an earlier member's that failed to publish.
    pub fn settle(&mut self, verified: bool) -> crate::Result<()> {
        self.go_on();
        let unsettled = self
            .unsettled
            .pop_front()
            .expect("only members opened are settled");
        match unsettled {
            Unsettled::Refused => {}
            Unsettled::Directory { meta, destination } => {
                self.forget_unsettled(&destination, true);
                if verified {
                    self.submit(Job::Directory { meta, destination });
                }
            }
            Unsettled::Output { pending, recheck } => {
                self.forget_unsettled(&pending.destination, false);
                if !verified {
                    drop_staged(&pending);
                    return self.publish_failure();
                }
                if recheck {
                    let (_, destination, existing) = self.destination(&pending.meta)?;
                    if self.overwrite == OverwritePolicy::Never
                        && exists(&destination, existing.as_ref())
                    {
                        drop_staged(&pending);
                        return Err(self.already_exists(&destination).into());
                    }
                }
                self.submit(Job::Output(pending));
            }
        }
        self.publish_failure()
    }

    fn forget_unsettled(&mut self, destination: &Path, directory: bool) {
        let relative = self.relative(destination);
        self.unsettled_paths.remove(relative, directory);
    }

    fn relative<'p>(&self, destination: &'p Path) -> &'p Path {
        destination
            .strip_prefix(self.out_dir)
            .expect("checked output path is under the output directory")
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
        let mut state = self.queue.state();
        state.tree(true)?;
        let overwrite = self.overwrite;
        let state = &mut *state;
        let (destination, writer, held): (_, Box<dyn Write>, _) = match &mut state.out_tree {
            Some(tree) => {
                let relative = destination
                    .strip_prefix(self.out_dir)
                    .expect("checked output path is under the output directory");
                let (dir, _) = tree.parent_dir(relative).map_err(|error| {
                    like_create_dir_all(refused_walk(error, &meta.name), &parent)
                })?;
                let name = relative.file_name().expect("output path has a name");
                let (destination, file) = match overwrite {
                    OverwritePolicy::Never => {
                        let file = dir.create_file(name, 0o666)?;
                        (destination, file)
                    }
                    OverwritePolicy::Rename => {
                        dir.create_numbered(&destination, 0o666, &mut state.renames)?
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
                let (_, destination, _) = state.destination(meta)?;
                let (destination, file) = crate::output_staging::open_in_place(
                    &destination,
                    overwrite,
                    &mut state.renames,
                )?;
                (destination, Box::new(file), None)
            }
        };
        self.pending = Some(PendingOutput {
            staged: None,
            staged_at: None,
            closed: None,
            held,
            stored,
            destination,
            meta: meta.clone(),
            link_target: None,
        });
        Ok(writer)
    }

    /// Stages a member's file, to publish once it verifies.
    fn open_staged(
        &mut self,
        stored: PathBuf,
        destination: PathBuf,
        meta: &crate::ExtractedEntryMeta,
    ) -> crate::Result<Box<dyn Write + Send>> {
        if self.storage.is_none() {
            self.storage = Some(self.queue.state().storage()?);
        }
        let storage = self.storage.as_ref().expect("made above");
        if storage.files.is_none() {
            let state = self.queue.state();
            let staging = state.staging.as_ref().expect("made with the storage");
            staging
                .reject_alias(&destination)
                .map_err(|error| refused_output(error, &meta.name))?;
        } else if destination.starts_with(&storage.root) {
            // Walked before the storage was there to refuse.
            return Err(refused_output(
                crate::Error::InvalidHeader("archive path conflicts with extraction storage"),
                &meta.name,
            ));
        }
        let index = self.staged.to_string();
        let mode = restored_early_mode(self.restore_modes, meta);
        let create_mode = mode.unwrap_or(0o666);
        let (staged, staged_at, file) = match &storage.files {
            Some((dir, root)) => {
                let name = std::ffi::OsString::from(index);
                let file = DeferredFile::new(dir.clone(), name.clone(), create_mode);
                (root.join(&name), Some((dir.clone(), name)), file)
            }
            None => {
                let staged = storage.root.join(index);
                let mut options = fs::OpenOptions::new();
                options.write(true).create_new(true);
                #[cfg(unix)]
                std::os::unix::fs::OpenOptionsExt::mode(&mut options, create_mode);
                let file = options.open(&staged)?;
                (staged, None, DeferredFile::from_file(file))
            }
        };
        self.staged += 1;
        let modified = self.modified_time(meta);
        let closed = Arc::new(CloseOutcome::default());
        self.pending = Some(PendingOutput {
            staged: Some(staged),
            staged_at,
            closed: Some(Arc::clone(&closed)),
            held: None,
            stored,
            destination,
            meta: meta.clone(),
            link_target: None,
        });
        Ok(Box::new(StagedFile {
            file,
            modified,
            mode,
            created_modes: self.created_modes.clone(),
            closed,
        }))
    }

    /// Publishes the member written last, once it has verified.
    pub fn publish_pending(&mut self) -> crate::Result<()> {
        self.go_on();
        self.publish_previous()
    }

    /// Queues the member written last, which has verified, and reports any failure to publish.
    fn publish_previous(&mut self) -> crate::Result<()> {
        let Some(pending) = self.pending.take() else {
            return self.publish_failure();
        };
        // The library reports a failed member before it asks for the next output.
        let failed = self.failed.is_some_and(|failed| {
            let mut failed = failed.lock().expect("failed members lock poisoned");
            let gone_past = failed.contains(&pending.meta.name);
            failed.clear();
            gone_past
        });
        if failed {
            drop_staged(&pending);
            return self.publish_failure();
        }
        if let Some(target) = pending.link_target {
            let target = std::mem::take(&mut *target.lock().expect("link target lock poisoned"));
            crate::output_links::check_legacy_symlink_target(
                &pending.meta.name,
                target.len() as u64,
                Some(&target),
            )?;
            return self.link_after_queue(
                &pending.meta,
                ExtractedLink::Symlink {
                    target: &target,
                    directory: false,
                },
            );
        }
        self.submit(Job::Output(pending));
        self.publish_failure()
    }

    /// Buffers a legacy symlink's target; the link is made once the target is verified.
    pub fn open_legacy_link(
        &mut self,
        meta: &crate::ExtractedEntryMeta,
    ) -> crate::Result<Box<dyn Write>> {
        self.go_on();
        self.publish_previous()?;
        let target = Arc::new(Mutex::new(Vec::new()));
        self.pending = Some(PendingOutput {
            staged: None,
            staged_at: None,
            closed: None,
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
        self.go_on();
        self.link_after_queue(meta, link)
    }

    /// A link finds what it names, and is made, once every earlier output is published.
    fn link_after_queue(
        &mut self,
        meta: &crate::ExtractedEntryMeta,
        link: ExtractedLink<'_>,
    ) -> crate::Result<()> {
        self.publish_previous()?;
        self.queue.wait();
        self.publish_failure()?;
        let (stored, destination, existing) = self.queue.state().destination(meta)?;
        let relative = destination
            .strip_prefix(self.out_dir)
            .expect("checked output path is under the output directory")
            .to_path_buf();
        let Some(target) = crate::output_links::link_target(
            self.out_dir,
            &relative,
            meta,
            link,
            self.queue.state().family,
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
        if !self.in_place
            && self.overwrite == OverwritePolicy::Never
            && exists(&destination, existing.as_ref())
        {
            return Err(self.already_exists(&destination).into());
        }
        let staged = (!self.in_place).then(|| self.staged.to_string());
        self.staged += usize::from(staged.is_some());
        self.queue
            .state()
            .make_link(meta, link, stored, &relative, &target, staged.as_deref())
    }

    #[cfg(all(test, unix))]
    fn modes_by_path(&mut self) -> Vec<PathBuf> {
        self.queue.wait();
        let state = self.queue.state();
        let modes = state.modes.as_ref().expect("restoring modes");
        modes.paths().map(Path::to_path_buf).collect()
    }

    /// A member still in flight when extraction failed never reaches its destination.
    pub fn finish(mut self, result: crate::Result<()>) -> crate::Result<ExtractedDir> {
        // Members not settled when extraction failed never verified.
        for unsettled in std::mem::take(&mut self.unsettled) {
            if let Unsettled::Output { pending, .. } = unsettled {
                drop_staged(&pending);
            }
        }
        let published = match &result {
            Ok(()) => self.publish_pending(),
            Err(error) => {
                let verified = matches!(
                    (failed_entry_name(error), &self.pending),
                    (Some(failed), Some(pending)) if failed != pending.meta.name.as_slice()
                );
                if verified {
                    // The extraction's own error wins over a failure to publish.
                    let _ = self.publish_previous();
                }
                Ok(())
            }
        };
        let Self {
            queue,
            flatten,
            overwrite,
            skipped_links,
            ..
        } = self;
        // A run that ended on a failure handed on drops the outputs held behind it.
        let (mut state, failures) = queue.finish();
        let mut restored = match &state.times {
            Some(times) => times.restore(),
            None => Ok(()),
        };
        // After the times: setting a time by path opens the file to read.
        if let (Ok(()), Some(modes)) = (&restored, state.modes.take()) {
            restored = modes.restore();
        }
        result?;
        published?;
        if let Some(failure) = failures.into_iter().next() {
            return Err(failure);
        }
        restored?;
        let mut paths = state.published.clone();
        if flatten && overwrite == OverwritePolicy::Always {
            // A member that replaced an earlier one is listed once, where it last landed.
            let mut seen = HashSet::new();
            paths.reverse();
            paths.retain(|path| seen.insert(path.clone()));
            paths.reverse();
        }
        Ok(ExtractedDir {
            paths,
            skipped_links,
        })
    }
}

impl Publishing {
    /// The output directory walked by descriptor, opened once it exists, or
    /// made first if `create`. `None` where the platform has no such walk.
    fn tree(&mut self, create: bool) -> crate::Result<Option<&mut OutputTree>> {
        if self.out_tree.is_none() && crate::output_tree::AVAILABLE {
            if create {
                fs::create_dir_all(&self.out_dir)?;
            }
            self.out_tree = OutputTree::open(&self.out_dir)?;
        }
        Ok(self.out_tree.as_mut())
    }

    /// Drops the walks' open directories, after a change made by path.
    fn forget_walks(&mut self) {
        if let Some(tree) = &mut self.out_tree {
            tree.forget();
        }
    }

    fn relative<'p>(&self, destination: &'p Path) -> &'p Path {
        destination
            .strip_prefix(&self.out_dir)
            .expect("checked output path is under the output directory")
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
        crate::filename::checked_output_path(&self.out_dir, &relative).map_err(refuse)?;
        if let Some(staging) = &self.staging {
            staging.reject_alias(&path).map_err(refuse)?;
        }
        Ok((stored, path, None))
    }

    /// Whether what opening finds at `destination` can still change as the outputs queued land.
    fn waits_for_queued(&self, destination: &Path, directory: bool) -> bool {
        self.queued.changes(self.relative(destination), directory)
    }

    fn is_published(&self, destination: &Path) -> bool {
        self.published.iter().any(|path| path == destination)
    }

    fn is_queued(&self, destination: &Path) -> bool {
        self.queued.holds(self.relative(destination))
    }

    fn note_queued(&mut self, destination: &Path, directory: bool) {
        let relative = self.relative(destination).to_path_buf();
        self.queued.add(&relative, directory);
    }

    fn note_published(&mut self, destination: &Path, directory: bool) {
        let relative = self.relative(destination).to_path_buf();
        self.queued.remove(&relative, directory);
    }

    /// Makes the staging storage. Where the output directory is walked by
    /// descriptor, so is the storage, and the walks refuse it.
    fn storage(&mut self) -> crate::Result<Storage> {
        if let Some(storage) = &self.storage {
            return Ok(storage.clone());
        }
        let staging = ExtractionStaging::new(&self.out_dir)?;
        let mut files = None;
        if let Some(tree) = self.tree(false)? {
            if let Some(mut storage) = OutputTree::open(&staging.root)? {
                tree.forbid(storage.identity());
                let dir = storage.file_dir(Path::new(STAGED_FILES))?;
                files = Some((dir, staging.root.join(STAGED_FILES)));
            }
        }
        let storage = Storage {
            root: staging.root.clone(),
            files,
        };
        self.staging = Some(staging);
        self.storage = Some(storage.clone());
        Ok(storage)
    }

    /// Makes a directory member, and any missing parents.
    fn create_directory(&mut self, meta: &crate::ExtractedEntryMeta) -> crate::Result<()> {
        // A symlink may have been linked into the way since it opened.
        let (stored, destination, existing) = self.destination(meta)?;
        if matches!(existing, Some(TreeEntry::Other(_))) {
            // What `create_dir_all` says of a file in the way.
            return Err(file_in_the_way().into());
        }
        let relative = self.relative(&destination).to_path_buf();
        match self.tree(true)? {
            Some(tree) => {
                tree.create_dirs(&relative).map_err(|error| {
                    like_create_dir_all(refused_walk(error, &meta.name), &destination)
                })?;
            }
            None => fs::create_dir_all(&destination)?,
        }
        self.record_published(stored, destination, meta, SetByPath::BOTH);
        Ok(())
    }

    fn publish_output(&mut self, pending: PendingOutput) -> crate::Result<()> {
        let Some(staged) = &pending.staged else {
            // Written in place: by descriptor, its time and mode go on through its own.
            let file = pending.held.as_ref().and_then(|held| held.get());
            let by_path = SetByPath {
                time: match (file, self.modified_time(&pending.meta)) {
                    (Some(file), Some(modified)) => file.set_modified(modified).is_err(),
                    _ => true,
                },
                mode: match (
                    file,
                    restored_early_mode(self.modes.is_some(), &pending.meta),
                ) {
                    (Some(file), Some(mode)) => set_file_mode(file, mode).is_err(),
                    _ => true,
                },
            };
            self.record_published(pending.stored, pending.destination, &pending.meta, by_path);
            return Ok(());
        };
        let closed = pending.closed.as_ref().expect("a staged file closes");
        if !closed.created.load(Ordering::Acquire) {
            return Err(crate::output_tree::never_created().into());
        }
        let time_set = closed.time_set.load(Ordering::Acquire);
        let mode_set = closed.mode_set.load(Ordering::Acquire);
        if let Some((dir, name)) = &pending.staged_at {
            if let Some((published, by_path)) =
                self.publish_by_descriptor(&pending, dir, name, time_set, mode_set)?
            {
                self.record_published(pending.stored, published, &pending.meta, by_path);
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
        let by_path = SetByPath {
            time: !time_set,
            mode: !mode_set,
        };
        self.record_published(pending.stored, destination, &pending.meta, by_path);
        Ok(())
    }

    fn modified_time(&self, meta: &crate::ExtractedEntryMeta) -> Option<SystemTime> {
        self.times.as_ref()?;
        meta.modified
            .and_then(|time| SystemTime::try_from(time).ok())
    }

    /// Publishes a file staged by descriptor, renaming it from the storage
    /// into the output directory's walked descriptors after giving it the
    /// time and mode it didn't take as it closed. Returns where it landed and
    /// what still needs setting, or `None` when the filesystem can't rename
    /// it into place.
    fn publish_by_descriptor(
        &mut self,
        pending: &PendingOutput,
        dir: &FileDir,
        name: &std::ffi::OsStr,
        time_set: bool,
        mode_set: bool,
    ) -> crate::Result<Option<(PathBuf, SetByPath)>> {
        let modified = self.modified_time(&pending.meta).filter(|_| !time_set);
        let early = restored_early_mode(self.modes.is_some(), &pending.meta);
        let mode = early.filter(|_| !mode_set);
        let set = (modified.is_none() && mode.is_none())
            || dir.set_metadata(name, modified, mode).is_ok();
        let by_path = SetByPath {
            time: !time_set && !set,
            mode: early.is_none() || (!mode_set && !set),
        };
        let relative = self.relative(&pending.destination).to_path_buf();
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
                &relative,
                &pending.destination,
                self.overwrite,
                &mut self.renames,
            )
            .map_err(|error| {
                like_create_dir_all(refused_walk(error, &pending.meta.name), parent)
            })?;
        Ok(published.map(|published| (published, by_path)))
    }

    /// Makes a link at `relative`, in place, or staged as `staged` and then published.
    fn make_link(
        &mut self,
        meta: &crate::ExtractedEntryMeta,
        link: ExtractedLink<'_>,
        stored: PathBuf,
        relative: &Path,
        target: &Path,
        staged: Option<&str>,
    ) -> crate::Result<()> {
        let copy_mode = restored_early_mode(self.modes.is_some(), meta);
        let Some(staged) = staged else {
            let created = create_link_output(
                &self.out_dir,
                relative,
                target,
                link,
                self.overwrite,
                &self.created,
                &mut self.renames,
                copy_mode,
            );
            // Made by path, which can remove a directory the walks hold.
            self.forget_walks();
            let (path, made) = created?;
            self.record_published(stored, path, meta, SetByPath::link(made));
            return Ok(());
        };
        let root = self.storage()?.root;
        let (staged, made) = create_link_output(
            &root,
            Path::new(staged),
            target,
            link,
            OverwritePolicy::Never,
            &self.created,
            &mut self.renames,
            copy_mode,
        )?;
        let source = match link {
            ExtractedLink::HardLink { .. } => {
                Some(link_source_path(target, &self.created)?.to_path_buf())
            }
            _ => None,
        };
        let destination = self.out_dir.join(relative);
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
        self.record_published(stored, published?, meta, SetByPath::link(made));
        Ok(())
    }

    /// Symlinks keep their own times and modes: setting them would follow the link.
    fn record_published(
        &mut self,
        stored: PathBuf,
        path: PathBuf,
        meta: &crate::ExtractedEntryMeta,
        by_path: SetByPath,
    ) {
        if let (Some(times), true) = (&mut self.times, by_path.time) {
            times.opened(path.clone(), meta);
            times.finish();
        }
        if let (Some(modes), true) = (&mut self.modes, by_path.mode) {
            modes.record(path.clone(), meta);
        }
        self.created.insert(stored, path.clone());
        self.published.push(path);
    }
}

impl PublishStep for Publishing {
    type Job = Job;

    fn publish(&mut self, job: Job) -> crate::Result<()> {
        let (destination, directory) = job.destination();
        let (destination, directory) = (destination.to_path_buf(), directory);
        let published = match job {
            Job::Output(pending) => self.publish_output(pending),
            Job::Directory { meta, .. } => self.create_directory(&meta),
        };
        self.note_published(&destination, directory);
        published
    }
}

/// What no descriptor set, so is set by path once extraction ends.
#[derive(Clone, Copy)]
struct SetByPath {
    time: bool,
    mode: bool,
}

impl SetByPath {
    const BOTH: Self = Self {
        time: true,
        mode: true,
    };

    fn link(made: MadeLink) -> Self {
        Self {
            time: made.is_file(),
            mode: matches!(made, MadeLink::Copy { mode_set: false }),
        }
    }
}

fn restored_early_mode(restore_modes: bool, meta: &crate::ExtractedEntryMeta) -> Option<u32> {
    restore_modes.then(|| early_mode(meta)).flatten()
}

fn exists(destination: &Path, existing: Option<&TreeEntry>) -> bool {
    match existing {
        Some(entry) => *entry != TreeEntry::Missing,
        None => fs::symlink_metadata(destination).is_ok(),
    }
}

fn drop_staged(pending: &PendingOutput) {
    if let Some(staged) = &pending.staged {
        let _ = fs::remove_file(staged);
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
    #[cfg(any(target_vendor = "apple", target_os = "linux", target_os = "android"))]
    return io::Error::from_raw_os_error(rustix::io::Errno::EXIST.raw_os_error());
    #[cfg(all(
        unix,
        not(any(target_vendor = "apple", target_os = "linux", target_os = "android"))
    ))]
    return io::Error::from_raw_os_error(libc::EEXIST);
    #[cfg(not(unix))]
    return io::ErrorKind::AlreadyExists.into();
}

/// `create_dir_all` reports a file where `directory` goes as `EEXIST`. A walk
/// by descriptor finds it can't open it as a directory, `ENOTDIR`, so it is
/// reported as `create_dir_all` would.
fn like_create_dir_all(error: crate::Error, directory: &Path) -> crate::Error {
    #[cfg(any(target_vendor = "apple", target_os = "linux", target_os = "android"))]
    {
        let not_a_directory = matches!(
            error.root_cause(),
            crate::Error::Io(io) if io
                .source()
                .downcast_ref::<io::Error>()
                .and_then(io::Error::raw_os_error)
                == Some(rustix::io::Errno::NOTDIR.raw_os_error())
        );
        if not_a_directory
            && fs::symlink_metadata(directory).is_ok_and(|metadata| !metadata.is_dir())
        {
            return file_in_the_way().into();
        }
    }
    #[cfg(all(
        unix,
        not(any(target_vendor = "apple", target_os = "linux", target_os = "android"))
    ))]
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

#[cfg(test)]
#[path = "output_dir_tests.rs"]
mod tests;

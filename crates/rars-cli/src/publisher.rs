use crate::output::{self, ExtractedOutput, ExtractionStaging, OverwritePolicy};
use rars::output_staging::{refused_output, FileIdentity, RenameCounters};
use rars::output_tree::OutputTree;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// A file staged under a name of its own in a directory held open.
pub(crate) struct Staged {
    pub(crate) dir: rars::output_tree::FileDir,
    pub(crate) name: std::ffi::OsString,
    /// Whether it took its early metadata as it closed: see [`output::StagedFile`].
    pub(crate) early_set: Arc<AtomicBool>,
}

/// What a member opened by descriptor leaves to do once it verifies.
pub(crate) enum Pending {
    /// Publish the file it staged.
    Staged(Staged),
    /// Finish the file it wrote in place.
    InPlace(InPlace),
    /// Record the directory it made in place, whose identity this is.
    InPlaceDirectory(FileIdentity),
}

/// A file written in place through the output tree.
pub(crate) struct InPlace {
    /// The file, once the library is done writing it: see [`rars::output_tree::HeldFile`].
    pub(crate) file: Arc<std::sync::OnceLock<fs::File>>,
    /// The directory it is in.
    pub(crate) dir: FileIdentity,
    /// The permission bits it was created with; `None` if it was there already.
    pub(crate) created_mode: Option<u32>,
    /// Its identity, under `Always`: a later member that reaches it by
    /// another name must not write over it.
    pub(crate) identity: Option<FileIdentity>,
}

/// An output opened and not yet in place, with what publishing it needs.
pub(crate) struct Unpublished {
    pub(crate) output: ExtractedOutput,
    /// Where it was written: in the staging storage, or in place.
    pub(crate) staged: PathBuf,
    pub(crate) pending: Option<Pending>,
    /// A link made by path, published by path.
    pub(crate) redirection: bool,
    /// For a hard link, where its target was when the link was made.
    pub(crate) hardlink_target: Option<PathBuf>,
    /// A directory whose existing time is taken just before it is published.
    pub(crate) time_on_publish: bool,
}

pub(crate) type PublishReport<'a> = dyn FnMut(&ExtractedOutput) + 'a;

/// Moves verified outputs into place in archive order, owning what that changes.
pub(crate) struct Publisher<'a> {
    out_dir: &'a Path,
    overwrite: OverwritePolicy,
    in_place: bool,
    repeats_allowed: bool,
    /// The output directory, walked by descriptor where the platform allows.
    out_tree: Option<OutputTree>,
    staging: Option<ExtractionStaging>,
    /// Files staged in the storage are published by descriptor.
    by_descriptor: bool,
    renames: RenameCounters,
    queue: VecDeque<Unpublished>,
    outputs: Vec<ExtractedOutput>,
    /// An output failed to publish: nothing after it is, as when it stopped the run.
    failed: bool,
    identities: HashSet<FileIdentity>,
    /// Where staged outputs were published, once a hard link may need to find one.
    published_paths: Option<HashMap<PathBuf, PathBuf>>,
    /// Where each stored path's latest output is now, for links to resolve.
    /// Built from `outputs` when a link or a discard first needs it, and
    /// kept up to date from then on: most archives have neither.
    created_paths: Option<HashMap<PathBuf, PathBuf>>,
    /// Whether files created in place in a directory with given permission
    /// bits have them, as [`output::CreatedModes`] says for staged files.
    in_place_modes: HashMap<(FileIdentity, u32), bool>,
    directory_times: Vec<(PathBuf, std::time::SystemTime)>,
    /// Told about each output once it is verified and in place.
    on_published: Option<Box<PublishReport<'a>>>,
}

impl<'a> Publisher<'a> {
    pub(crate) fn new(out_dir: &'a Path, overwrite: OverwritePolicy, in_place: bool) -> Self {
        Self {
            out_dir,
            overwrite,
            in_place,
            repeats_allowed: false,
            out_tree: None,
            staging: None,
            by_descriptor: false,
            renames: Default::default(),
            queue: VecDeque::new(),
            outputs: Vec::new(),
            failed: false,
            identities: HashSet::new(),
            published_paths: None,
            created_paths: None,
            in_place_modes: HashMap::new(),
            directory_times: Vec::new(),
            on_published: None,
        }
    }

    pub(crate) fn set_repeats_allowed(&mut self, allowed: bool) {
        self.repeats_allowed = allowed;
    }

    pub(crate) fn report_to(&mut self, report: Box<PublishReport<'a>>) {
        self.on_published = Some(report);
    }

    pub(crate) fn len(&self) -> usize {
        self.outputs.len() + self.queue.len()
    }

    /// The output tree, opened on first use: a queued publish adds to it.
    pub(crate) fn tree(&mut self) -> rars::Result<Option<&mut OutputTree>> {
        if self.out_tree.is_none() {
            self.out_tree = OutputTree::open(self.out_dir)?;
        }
        Ok(self.out_tree.as_mut())
    }

    /// Whether members are written in place through the output tree,
    /// creating the output directory and opening it if need be.
    pub(crate) fn in_place_tree(&mut self) -> rars::Result<bool> {
        if self.out_tree.is_none() && rars::output_tree::AVAILABLE {
            fs::create_dir_all(self.out_dir)?;
            self.out_tree = OutputTree::open(self.out_dir)?;
        }
        Ok(self.out_tree.is_some())
    }

    pub(crate) fn opened_tree(&mut self) -> Option<&mut OutputTree> {
        self.out_tree.as_mut()
    }

    /// Something changed the output directory by path: the walks no longer describe it.
    pub(crate) fn forget_walks(&mut self) {
        if let Some(tree) = &mut self.out_tree {
            tree.forget();
        }
    }

    /// The staging storage. Publishing never changes it.
    pub(crate) fn staging(&self) -> Option<&ExtractionStaging> {
        self.staging.as_ref()
    }

    /// `by_descriptor` when files stage in a staging tree.
    pub(crate) fn start_staging(&mut self, staging: ExtractionStaging, by_descriptor: bool) {
        self.staging = Some(staging);
        self.by_descriptor = by_descriptor;
    }

    /// Opening numbers names only in place, where nothing queues.
    pub(crate) fn renames(&mut self) -> &mut RenameCounters {
        &mut self.renames
    }

    /// Whether this run published `identity`. A queued publish can add it.
    pub(crate) fn published(&self, identity: &FileIdentity) -> bool {
        self.identities.contains(identity)
    }

    /// Whether this run published or made the directory `identity`.
    pub(crate) fn made_here(&self, identity: &FileIdentity) -> bool {
        self.identities.contains(identity)
            || self
                .out_tree
                .as_ref()
                .is_some_and(|tree| tree.created(identity))
    }

    /// A queued publish can create or change `destination`.
    pub(crate) fn record_directory_time(
        &mut self,
        destination: &Path,
        meta: &rars::ExtractedEntryMeta,
    ) -> rars::Result<()> {
        if let Some(time) = directory_time(destination, meta)? {
            self.directory_times.push(time);
        }
        Ok(())
    }

    /// A hard link was made: from now on, remember where staged outputs land.
    pub(crate) fn track_hard_links(&mut self) {
        self.published_paths.get_or_insert_with(HashMap::new);
    }

    /// Builds [`Self::created_paths`] if nothing has needed it yet, from what is published, queued and `opened`.
    pub(crate) fn link_paths(
        &mut self,
        opened: &VecDeque<Unpublished>,
    ) -> (&mut HashMap<PathBuf, PathBuf>, &mut RenameCounters) {
        let created = self.created_paths.get_or_insert_with(|| {
            let mut created = HashMap::new();
            for output in &self.outputs {
                created.insert(output.stored.clone(), output.path.clone());
            }
            for unpublished in self.queue.iter().chain(opened) {
                created.insert(
                    unpublished.output.stored.clone(),
                    unpublished.staged.clone(),
                );
            }
            created
        });
        (created, &mut self.renames)
    }

    /// A newly opened output for `stored` is at `staged`.
    pub(crate) fn note_created(&mut self, stored: &Path, staged: &Path) {
        if let Some(created) = &mut self.created_paths {
            created.insert(stored.to_path_buf(), staged.to_path_buf());
        }
    }

    /// The output at `staged`, one of `opened`, is dropped.
    pub(crate) fn forget_created(&mut self, opened: &VecDeque<Unpublished>, staged: &Path) {
        let (created, _) = self.link_paths(opened);
        created.retain(|_, path| path != staged);
    }

    pub(crate) fn queue(&mut self, verified: Unpublished) {
        self.queue.push_back(verified);
    }

    pub(crate) fn publish_queued(&mut self) -> rars::Result<()> {
        if self.failed && !self.queue.is_empty() {
            return Err(rars::Error::InvalidArgument(
                "an earlier output could not be published",
            ));
        }
        while let Some(mut next) = self.queue.pop_front() {
            if let Err(error) = self.publish(&mut next) {
                self.failed = true;
                return Err(error);
            }
            if let Some(report) = &mut self.on_published {
                report(&next.output);
            }
            self.outputs.push(next.output);
        }
        Ok(())
    }

    pub(crate) fn finish(mut self) -> rars::Result<Vec<ExtractedOutput>> {
        self.publish_queued()?;
        for (path, modified) in &self.directory_times {
            rars::output_times::set_modified_time(path, *modified)?;
        }
        Ok(std::mem::take(&mut self.outputs))
    }

    // Publish new inodes rather than truncating any existing hard-link target.
    fn publish(&mut self, next: &mut Unpublished) -> rars::Result<()> {
        if next.time_on_publish {
            self.record_directory_time(&next.output.path, &next.output.meta)?;
            next.time_on_publish = false;
        }
        if self.in_place {
            // Checked and written at its destination when it was opened.
            match next.pending.take() {
                Some(Pending::InPlace(pending)) => self.finish_in_place(pending, &mut next.output),
                Some(Pending::InPlaceDirectory(identity)) => {
                    self.identities.insert(identity);
                }
                _ => self.record_identity(&next.staged)?,
            }
            return Ok(());
        }
        if !self.publish_by_descriptor(next)? {
            self.publish_by_path(next)?;
        }
        let output = &next.output;
        // Later redirections resolve this entry at its published location.
        if let Some(created) = &mut self.created_paths {
            if created.get(&output.stored) == Some(&next.staged) {
                created.insert(output.stored.clone(), output.path.clone());
            }
        }
        // A hard link staged before this was published finds it here.
        if let Some(published) = &mut self.published_paths {
            published.insert(std::mem::take(&mut next.staged), output.path.clone());
        }
        Ok(())
    }

    /// Finishes a file written in place once it has verified: records its
    /// identity and sets its time and mode through its descriptor. If it
    /// can't, they wait for the end and are set by path.
    fn finish_in_place(&mut self, pending: InPlace, output: &mut ExtractedOutput) {
        let InPlace {
            file,
            dir,
            created_mode,
            identity,
        } = pending;
        if let Some(identity) = identity {
            self.identities.insert(identity);
        }
        // A writer the library still holds keeps the file to itself.
        let (Some(file), Some((modified, mode))) =
            (file.get(), output::early_file_metadata(output))
        else {
            return;
        };
        let modes = &mut self.in_place_modes;
        let set = (|| {
            if let Some(modified) = modified {
                file.set_modified(modified)?;
            }
            if let Some(mode) = mode {
                // Created with its mode, it keeps it unless the umask or the
                // directory's default ACL cleared some.
                let kept = created_mode == Some(mode)
                    && *modes
                        .entry((dir, mode))
                        .or_insert_with(|| output::has_mode(file, mode));
                if !kept {
                    output::set_file_mode(file, mode)?;
                }
            }
            std::io::Result::Ok(())
        })();
        output.restore_metadata &= set.is_err();
    }

    /// Publishes a staged file or directory relative to the open output
    /// directories. `false` leaves it to [`Self::publish_by_path`]: there are
    /// no open directories, it is a redirection, or the filesystem cannot
    /// rename it into place.
    fn publish_by_descriptor(&mut self, next: &mut Unpublished) -> rars::Result<bool> {
        let repeats_allowed = self.repeats_allowed;
        let (Some(out_tree), true) = (&mut self.out_tree, self.by_descriptor) else {
            return Ok(false);
        };
        if next.redirection {
            return Ok(false);
        }
        let output = &mut next.output;
        let destination = &output.path;
        let relative = destination
            .strip_prefix(self.out_dir)
            .map_err(|_| rars::Error::InvalidHeader("unsafe archive path"))?;
        let name = &output.meta.name;
        let refuse = |error| output::refused_path(error, name);
        let directory = output.meta.is_directory;
        // Under `Never` an existing file already stops the rename, so only
        // `Always` needs to know which files this run wrote.
        let tracked = !repeats_allowed && self.overwrite == OverwritePolicy::Always;
        let repeated = || {
            Err(rars::Error::InvalidHeader(
                "multiple archive entries map to the same output path",
            ))
        };
        if directory {
            // Creating a directory already there changes nothing.
            let identity = match out_tree.create_dirs(relative) {
                Ok(identity) => identity,
                Err(error) => {
                    let ours = |identity| self.identities.contains(&identity);
                    if !repeats_allowed
                        && out_tree
                            .identity_of(relative)
                            .is_ok_and(|identity| identity.is_some_and(ours))
                    {
                        return repeated();
                    }
                    return Err(refuse(error));
                }
            };
            if !self.identities.insert(identity) && !repeats_allowed {
                return repeated();
            }
            return Ok(true);
        }
        if tracked {
            if let Some(identity) = out_tree.identity_of(relative).map_err(refuse)? {
                if self.identities.contains(&identity) || out_tree.created(&identity) {
                    return repeated();
                }
            }
        }
        let Some(Pending::Staged(staged)) = &next.pending else {
            return Ok(false);
        };
        let early = output::early_file_metadata(output);
        if let (Some((modified, mode)), false) = (early, staged.early_set.load(Ordering::Acquire)) {
            staged.dir.set_metadata(&staged.name, modified, mode)?;
        }
        let published = staged
            .dir
            .publish(
                &staged.name,
                out_tree,
                relative,
                destination,
                self.overwrite,
                &mut self.renames,
            )
            .map_err(|error| match error {
                // Opening it refused anything already there, so another
                // member was published there since.
                rars::Error::Io(error)
                    if error.kind == std::io::ErrorKind::AlreadyExists
                        && self.overwrite == OverwritePolicy::Never =>
                {
                    rars::Error::InvalidHeader(
                        "multiple archive entries map to the same output path",
                    )
                }
                error => refuse(error),
            })?;
        let Some(published) = published else {
            return Ok(false);
        };
        if tracked {
            if let Some(identity) = out_tree.identity_of(relative).map_err(refuse)? {
                self.identities.insert(identity);
            }
        }
        output.path = published;
        // Set on the staged file, which keeps them through the rename.
        output.restore_metadata &= early.is_none();
        Ok(true)
    }

    fn publish_by_path(&mut self, next: &mut Unpublished) -> rars::Result<()> {
        // Whatever this changes, the open directories no longer describe.
        self.forget_walks();
        let staged = &next.staged;
        let output = &next.output;
        let name = &output.meta.name;
        let relative = output
            .path
            .strip_prefix(self.out_dir)
            .map_err(|_| rars::Error::InvalidHeader("unsafe archive path"))?;
        let destination = output::checked_output_path(self.out_dir, relative)
            .map_err(|error| refused_output(error, name))?;
        // The alias check resolves the destination already when it exists.
        let existing = match &self.staging {
            Some(staging) => staging
                .reject_alias(&destination)?
                .and_then(|resolved| FileIdentity::resolved(resolved).ok()),
            None => FileIdentity::of(&destination).ok(),
        };
        if let Some(identity) = existing {
            if self.identities.contains(&identity) && !self.repeats_allowed {
                return Err(rars::Error::InvalidHeader(
                    "multiple archive entries map to the same output path",
                ));
            }
        }
        if fs::symlink_metadata(staged)?.is_dir() {
            fs::create_dir_all(&destination)?;
        } else {
            fs::create_dir_all(destination.parent().expect("validated path has parent"))?;
            output::checked_output_path(self.out_dir, relative)
                .map_err(|error| refused_output(error, name))?;
            if self.overwrite == OverwritePolicy::Always && next.redirection {
                match fs::symlink_metadata(&destination) {
                    Ok(metadata) if metadata.is_dir() => fs::remove_dir(&destination)?,
                    Ok(_) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
            }
            // A hard link's target was published before the link was staged.
            let hardlink_target = next.hardlink_target.as_deref().map(|target| {
                self.published_paths
                    .as_ref()
                    .and_then(|published| published.get(target))
                    .map_or(target, PathBuf::as_path)
            });
            let published = output::publish_verified_output(
                staged,
                &destination,
                self.overwrite,
                hardlink_target,
                &mut self.renames,
            )?;
            next.output.path = published;
        }
        let destination = next.output.path.clone();
        self.record_identity(&destination)
    }

    // Symlinks may be dangling; their destination entries were reserved on open.
    fn record_identity(&mut self, destination: &Path) -> rars::Result<()> {
        if let Ok(identity) = FileIdentity::of(destination) {
            if !fs::symlink_metadata(destination)?.file_type().is_symlink() {
                self.identities.insert(identity);
            }
        }
        Ok(())
    }
}

/// The time to restore on a directory member with none of its own: the one
/// already at `destination`, before extraction changes it.
fn directory_time(
    destination: &Path,
    meta: &rars::ExtractedEntryMeta,
) -> rars::Result<Option<(PathBuf, std::time::SystemTime)>> {
    if !meta.is_directory || meta.modified.is_some() {
        return Ok(None);
    }
    match fs::metadata(destination) {
        Ok(metadata) if metadata.is_dir() => {
            Ok(Some((destination.to_path_buf(), metadata.modified()?)))
        }
        Ok(_) => Ok(None),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

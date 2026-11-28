mod publisher;
mod staged;

use crate::output_links::{create_link_output, link_source_path};
use crate::output_staging::{refused_output, ExtractionStaging, FileIdentity, OverwritePolicy};
use crate::output_tree::{OutputTree, TreeEntry};
pub use publisher::PublishReport;
use publisher::{InPlace, Pending, Publisher, Staged, Unpublished};
use staged::open_output_writer;
pub use staged::{restore_output_metadata, ExtractedOutput};
use std::collections::{HashSet, VecDeque};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

pub type Selection<'a> = dyn Fn(&crate::ExtractedEntryMeta) -> bool + Send + 'a;

/// What the engine passed over that its caller may want to say.
#[derive(Debug, Clone, Copy)]
pub enum Warning<'w> {
    /// A member with no name settled; it was decoded, never written.
    Unnamed,
    /// A link whose target leaves the output directory was left out.
    SkippedLink { name: &'w [u8], target: &'w [u8] },
}

pub type Warn<'a> = dyn FnMut(Warning<'_>) + Send + 'a;

/// Where files stage in a staging storage walked by descriptor.
const STAGED_FILES: &str = "files";
/// Where links stage in a staging storage walked by descriptor.
const STAGED_LINKS: &str = "links";

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
/// separator.
fn rar50_relative_path(name: &[u8], unix_host: bool) -> crate::Result<PathBuf> {
    let native = crate::output_links::rar50_native_name(name, unix_host);
    crate::filename::relative_path(&native, false)
}

/// Extraction into a directory: a member's output is published only once it settles verified.
pub struct ExtractEngine<'a> {
    out_dir: &'a Path,
    overwrite: OverwritePolicy,
    in_place: bool,
    flatten: bool,
    flat_names: crate::output_staging::FlatNames,
    family: crate::ArchiveFamily,
    legacy_name_encoding: Option<crate::filename::LegacyNameEncoding>,
    unpublished: VecDeque<Unpublished>,
    publisher: Publisher,
    planned_paths: HashSet<PathBuf>,
    /// Where the staging storage is, once made: publishing never moves it.
    staging_at: Option<PathBuf>,
    /// The staging storage, walked the same way; present only with `out_tree`.
    /// Files stage there under names of their own in [`STAGED_FILES`], and
    /// links under their own paths in [`STAGED_LINKS`].
    staging_tree: Option<OutputTree>,
    /// [`STAGED_FILES`], once a file has staged there, and its path.
    staging_files: Option<(crate::output_tree::FileDir, PathBuf)>,
    /// Names taken in [`STAGED_FILES`].
    staged_count: u64,
    /// Which permission bits files created in [`STAGED_FILES`] keep.
    created_modes: crate::output_modes::CreatedModes,
    restore_modes: bool,
    /// So a hard link or copy naming a symlink left out fails as its own member.
    skipped_symlinks: Option<HashSet<PathBuf>>,
    staged_directories: HashSet<FileIdentity>,
    skipped_links: usize,
    /// Members whose header gives no name: decoded and checked, never written.
    skipped_unnamed: usize,
    /// Leaves a file already at its destination alone instead of failing.
    skip_existing: bool,
    /// Lets members that land on one path overwrite each other with
    /// [`OverwritePolicy::Always`], as flattening does.
    overwrite_repeats: bool,
    /// Members `skip_existing` left alone.
    kept_existing: usize,
    /// Members outside this set are decoded but not written.
    selected: Option<Box<Selection<'a>>>,
    warn: Option<Box<Warn<'a>>>,
    exists_hint: Option<&'static str>,
    /// A directory member with no time keeps the one already there.
    keep_directory_time: bool,
    /// Outputs before this index have verified: see [`Self::settle`].
    settled: usize,
    /// Staged files are created as they are written, since the library may write them on other threads.
    written_elsewhere: bool,
    /// What each member opened and not yet settled left.
    unsettled: VecDeque<Opened>,
}

/// What opening a member left, until it settles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Opened {
    /// A staged output.
    Output,
    /// Nothing to publish; `unnamed` if left out for having no name.
    Nothing { unnamed: bool },
    /// The open failed.
    Refused,
}

impl<'a> ExtractEngine<'a> {
    /// In place, a member is written at its destination as it opens instead of staged.
    pub fn new(
        out_dir: &'a Path,
        overwrite: OverwritePolicy,
        in_place: bool,
        flatten: bool,
        family: crate::ArchiveFamily,
    ) -> Self {
        let mut state = Self {
            out_dir,
            overwrite,
            in_place,
            flatten,
            flat_names: Default::default(),
            family,
            legacy_name_encoding: None,
            unpublished: VecDeque::new(),
            publisher: Publisher::new(out_dir, overwrite, in_place),
            planned_paths: HashSet::new(),
            staging_at: None,
            staging_tree: None,
            staging_files: None,
            staged_count: 0,
            created_modes: Default::default(),
            restore_modes: true,
            skipped_symlinks: None,
            staged_directories: HashSet::new(),
            skipped_links: 0,
            skipped_unnamed: 0,
            skip_existing: false,
            overwrite_repeats: false,
            kept_existing: 0,
            selected: None,
            warn: None,
            exists_hint: None,
            keep_directory_time: true,
            settled: 0,
            written_elsewhere: false,
            unsettled: VecDeque::new(),
        };
        state
            .publisher
            .state()
            .set_repeats_allowed(state.repeats_allowed());
        // In place, opening writes the destination; flattened, it claims names publishing keeps.
        state.publisher.publish_on_thread(!in_place && !flatten);
        state
    }

    /// For callers whose own output follows each publish as it happens.
    pub fn publish_on_calling_thread(&mut self) {
        self.publisher.publish_on_thread(false);
    }

    pub fn ignore_modes(&mut self) {
        self.restore_modes = false;
    }

    pub fn skip_symlinks(&mut self) {
        self.skipped_symlinks = Some(HashSet::new());
    }

    /// Leaves a file already at a member's destination alone instead of failing.
    pub fn skip_existing(&mut self) {
        self.skip_existing = true;
    }

    /// Under [`OverwritePolicy::Always`], a later member replaces an earlier one on its path.
    pub fn allow_overwrite_repeats(&mut self) {
        self.overwrite_repeats = true;
        self.publisher
            .state()
            .set_repeats_allowed(self.repeats_allowed());
    }

    /// Told about each output once it is verified and in place.
    pub fn report_to(&mut self, report: Box<PublishReport>) {
        self.publisher.report_to(report);
    }

    pub fn warn_to(&mut self, warn: Box<Warn<'a>>) {
        self.warn = Some(warn);
    }

    /// Members outside `selected` are decoded but not written.
    pub fn select(&mut self, selected: Box<Selection<'a>>) {
        self.selected = Some(selected);
    }

    /// `Never` refuses with "`<path>` already exists" and this, not the system's "File exists".
    pub fn exists_hint(&mut self, hint: &'static str) {
        self.exists_hint = Some(hint);
    }

    /// A directory member with no time of its own takes the time extraction leaves it.
    pub fn leave_directory_time(&mut self) {
        self.keep_directory_time = false;
    }

    pub fn legacy_name_encoding(&mut self, encoding: Option<crate::filename::LegacyNameEncoding>) {
        self.legacy_name_encoding = encoding;
    }

    /// Writers are dropped on other threads (RAR 5's write lane): create staged files there.
    pub fn written_elsewhere(&mut self, elsewhere: bool) {
        self.written_elsewhere = elsewhere;
    }

    pub fn in_place(&self) -> bool {
        self.in_place
    }

    /// Whether a member may open before the ones ahead of it settle.
    pub fn can_open_ahead(&self) -> bool {
        // In place, a member opened after a failure would already be at its
        // destination. Flattened, a member can stage where an earlier one is
        // still staged. Both keep opening each member once the last verified.
        !self.in_place && !self.flatten
    }

    /// Outputs opened so far, including those published.
    pub fn opened(&self) -> usize {
        self.publisher.len() + self.unpublished.len()
    }

    pub fn last_opened(&self) -> Option<&ExtractedOutput> {
        self.unpublished
            .back()
            .map(|unpublished| &unpublished.output)
    }

    pub fn skipped_links(&self) -> usize {
        self.skipped_links
    }

    pub fn skipped_unnamed(&self) -> usize {
        self.skipped_unnamed
    }

    pub fn kept_existing(&self) -> usize {
        self.kept_existing
    }

    fn warn(&mut self, warning: Warning<'_>) {
        if let Some(warn) = &mut self.warn {
            warn(warning);
        }
    }

    pub fn open_settled(
        &mut self,
        meta: &crate::ExtractedEntryMeta,
    ) -> crate::Result<Box<dyn Write + Send>> {
        let outputs = self.opened();
        let opened = self.open_entry(meta);
        self.unsettled.push_back(match &opened {
            Ok(_) if self.opened() > outputs => Opened::Output,
            Ok(_) => Opened::Nothing {
                unnamed: meta.name.is_empty(),
            },
            Err(_) => Opened::Refused,
        });
        opened
    }

    /// A member's open failed before it reached [`Self::open_settled`]; it still settles.
    pub fn refuse(&mut self, error: crate::Error) -> crate::Error {
        self.unsettled.push_back(Opened::Refused);
        error
    }

    /// Opens nothing for a member the caller leaves out; it still settles.
    pub fn pass_over(&mut self) -> Box<dyn Write + Send> {
        self.unsettled.push_back(Opened::Nothing { unnamed: false });
        Box::new(std::io::sink())
    }

    /// The library is done with the oldest member opened and not settled.
    /// A verified member's output now counts as verified and is published,
    /// so a failure to publish it is its own; a failed one's is dropped.
    /// Returns whether its open had failed.
    pub fn settle(&mut self, verified: bool) -> crate::Result<bool> {
        let opened = self
            .unsettled
            .pop_front()
            .expect("the library settles only members it opened");
        match opened {
            Opened::Refused => return Ok(true),
            Opened::Output if !verified => {
                self.discard_output(self.settled);
                return Ok(false);
            }
            Opened::Nothing { .. } if !verified => return Ok(false),
            Opened::Nothing { unnamed: true } => {
                self.warn(Warning::Unnamed);
                self.skipped_unnamed += 1;
            }
            Opened::Output | Opened::Nothing { .. } => {}
        }
        self.publish_verified()?;
        if opened == Opened::Output {
            self.settled += 1;
            self.publish_verified()?;
        }
        Ok(false)
    }

    /// Drops an output that is not to be published, and what it staged.
    fn discard_output(&mut self, index: usize) {
        let staged = self.unpublished[index].staged.clone();
        self.publisher.wait();
        self.publisher
            .link_state()
            .forget_created(&self.unpublished, &staged);
        self.unpublished.remove(index);
        if !self.in_place {
            let _ = fs::remove_file(&staged);
        }
    }

    // Decode names once at the filesystem boundary, retaining the archive's
    // raw identity for errors and publication. RAR5 Unix hosts map to AttrSource::Unix.
    fn entry_path(&self, meta: &crate::ExtractedEntryMeta) -> crate::Result<(Vec<u8>, PathBuf)> {
        let unsafe_path = |_| crate::Error::InvalidHeader("unsafe archive path");
        if self.family == crate::ArchiveFamily::Rar50Plus {
            let unix_host = meta.attr_source == crate::AttrSource::Unix;
            let path = rar50_relative_path(&meta.name, unix_host).map_err(unsafe_path)?;
            Ok((meta.name.clone(), path))
        } else {
            let name = crate::filename::decoded_name(
                &meta.name,
                meta.name_is_unicode,
                self.legacy_name_encoding,
            )?
            .into_owned();
            let path = crate::filename::relative_path(&name, true).map_err(unsafe_path)?;
            Ok((name, path))
        }
    }

    fn open_entry(
        &mut self,
        meta: &crate::ExtractedEntryMeta,
    ) -> crate::Result<Box<dyn Write + Send>> {
        // Publishes links reported since the last settle, unless a member before this one is unsettled.
        if self.settled == self.unpublished.len() {
            self.publish_verified()?;
        }
        self.publisher.publish_failure()?;
        if self.unnamed(meta) {
            return Ok(Box::new(std::io::sink()));
        }
        let (name, stored) = self.entry_path(meta)?;
        if self.flatten && meta.is_directory {
            return Ok(Box::new(std::io::sink()));
        }
        let relative = self.output_relative(&stored);
        self.wait_for_queued(&relative, meta.is_directory)?;
        let (destination, existing) = self
            .checked_destination(&relative)
            .map_err(|error| staged::refused_path(error, &meta.name))?;
        if self.passed_over(meta, &destination, existing.as_ref()) {
            return Ok(Box::new(std::io::sink()));
        }
        self.claim_flat_name(&relative, &meta.name)?;
        self.reserve_output_path(destination.clone())?;
        // Staged, the members before this one may not be published yet: the
        // time is taken as it is published.
        if self.in_place && self.keep_directory_time {
            self.publisher
                .state()
                .record_directory_time(&destination, meta)?;
        }
        self.prepare_staged_path(&destination, meta.is_directory, existing.as_ref())?;
        let by_descriptor = self.in_place && self.publisher.state().in_place_tree()?;
        let (path, staged, pending, writer) = match &mut self.staging_tree {
            Some(tree) => {
                // Each member stages under a name of its own, so only
                // publishing it can meet another member's output.
                let index = self.staged_count;
                self.staged_count += 1;
                let name = std::ffi::OsString::from(index.to_string());
                if self.staging_files.is_none() {
                    let dir = tree.file_dir(Path::new(STAGED_FILES))?;
                    let root = self.staging_root();
                    self.staging_files = Some((dir, root.join(STAGED_FILES)));
                }
                let (dir, root) = self.staging_files.as_ref().expect("made above");
                let path = root.join(&name);
                let (writer, staged): (Box<dyn Write + Send>, _) = if meta.is_directory {
                    // Publishing creates it.
                    (Box::new(std::io::sink()), None)
                } else {
                    let dir = dir.clone();
                    let (mut file, early_set) = staged::StagedFile::deferred(
                        dir.clone(),
                        name.clone(),
                        meta,
                        self.restore_modes,
                        self.created_modes.clone(),
                    );
                    if !self.written_elsewhere {
                        file.create()?;
                    }
                    let staged = Staged {
                        dir,
                        name,
                        early_set,
                    };
                    (Box::new(file), Some(staged))
                };
                (None, path, staged.map(Pending::Staged), writer)
            }
            None if by_descriptor => {
                let (path, pending, writer) =
                    self.open_in_place(&relative, destination.clone(), meta, existing.as_ref())?;
                (Some(path.clone()), path, Some(pending), writer)
            }
            None => {
                let policy = self.staged_policy();
                let root = self.staging_root();
                let (path, writer) = open_output_writer(
                    &root,
                    &relative,
                    meta.is_directory,
                    policy,
                    self.publisher.state().renames(),
                )?;
                self.record_staged_path(&path, meta.is_directory)?;
                (Some(path.clone()), path, None, writer)
            }
        };
        // In place, `Rename` chose the name when it opened.
        let path = match path {
            Some(path) if self.in_place => path,
            _ => destination,
        };
        self.publisher.note_created(&stored, &staged);
        self.unpublished.push_back(Unpublished {
            output: ExtractedOutput {
                name,
                stored,
                path,
                meta: meta.clone(),
                restore_metadata: true,
                restore_mode: self.restore_modes,
            },
            staged,
            pending,
            redirection: false,
            hardlink_target: None,
            time_on_publish: !self.in_place && self.keep_directory_time,
        });
        Ok(writer)
    }

    pub fn create_link(
        &mut self,
        meta: &crate::ExtractedEntryMeta,
        link: crate::ExtractedLink<'_>,
    ) -> crate::Result<()> {
        if !self.unsettled.is_empty() {
            return Err(crate::Error::InvalidArgument(
                "a link was reported before the members ahead of it settled",
            ));
        }
        self.publish_verified()?;
        // The link finds its target where it was published.
        self.publisher.wait();
        self.publisher.publish_failure()?;
        if self.unnamed(meta) {
            return Ok(());
        }
        let (name, stored) = self.entry_path(meta)?;
        if let (
            Some(skipped),
            crate::ExtractedLink::Symlink { .. } | crate::ExtractedLink::Junction { .. },
        ) = (&mut self.skipped_symlinks, link)
        {
            skipped.insert(stored);
            return Ok(());
        }
        let relative = self.output_relative(&stored);
        let destination = staged::checked_output_path(self.out_dir, &relative)
            .map_err(|error| refused_output(error, &meta.name))?;
        if self.passed_over(meta, &destination, None) {
            return Ok(());
        }
        let Some(target) = crate::output_links::link_target(
            self.out_dir,
            &relative,
            meta,
            link,
            self.family,
            self.flatten,
        )?
        else {
            self.warn(Warning::SkippedLink {
                name: &name,
                target: link.target(),
            });
            self.skipped_links += 1;
            return Ok(());
        };
        if matches!(
            link,
            crate::ExtractedLink::HardLink { .. } | crate::ExtractedLink::FileCopy { .. }
        ) && self
            .skipped_symlinks
            .as_ref()
            .is_some_and(|skipped| skipped.contains(&target))
        {
            return Err(crate::Error::InvalidArgument(
                "hard link or file copy target is a symbolic link left out",
            ));
        }
        self.claim_flat_name(&relative, &meta.name)?;
        self.reserve_output_path(destination.clone())?;
        self.prepare_staged_path(&destination, false, None)?;
        let mut staging = self.staging_root();
        if self.staging_tree.is_some() {
            staging.push(STAGED_LINKS);
        }
        let policy = self.staged_policy();
        let mut publisher = self.publisher.link_state();
        let (created_paths, renames) = publisher.link_paths(&self.unpublished);
        let created = create_link_output(
            &staging,
            &relative,
            &target,
            link,
            policy,
            created_paths,
            renames,
            None,
        );
        if self.in_place {
            // Made by path, which can remove a directory the walks hold.
            publisher.forget_walks();
        }
        let (path, made) = created?;
        let restore_metadata = made.is_file();
        let (created_paths, _) = publisher.link_paths(&self.unpublished);
        let hardlink_target = match link {
            crate::ExtractedLink::HardLink { .. } => {
                Some(link_source_path(&target, created_paths)?.to_path_buf())
            }
            _ => None,
        };
        created_paths.insert(stored.clone(), path.clone());
        if hardlink_target.is_some() {
            publisher.track_hard_links();
        }
        drop(publisher);
        self.record_staged_path(&path, false)?;
        self.unpublished.push_back(Unpublished {
            output: ExtractedOutput {
                name,
                stored,
                path: if self.in_place {
                    path.clone()
                } else {
                    destination
                },
                meta: meta.clone(),
                restore_metadata,
                restore_mode: self.restore_modes,
            },
            staged: path,
            pending: None,
            redirection: true,
            hardlink_target,
            time_on_publish: false,
        });
        // The library reports a link once every member before it has settled.
        self.settled = self.unpublished.len();
        Ok(())
    }

    /// Whether a member has no name to write it under, as when its header's
    /// name field starts with a NUL. As the reference does, extraction leaves it out;
    /// its data is still decoded, so a solid stream stays in step.
    fn unnamed(&self, meta: &crate::ExtractedEntryMeta) -> bool {
        // Warned about once it settles, in archive order.
        meta.name.is_empty()
    }

    /// Waits for the outputs queued ahead of a member when one could change
    /// what opening it finds, so it finds what it would at one thread.
    fn wait_for_queued(&mut self, relative: &Path, directory: bool) -> crate::Result<()> {
        if !self.publisher.queued_changes(relative, directory) {
            return Ok(());
        }
        self.queued_failure()
    }

    fn output_relative<'p>(&self, stored: &'p Path) -> std::borrow::Cow<'p, Path> {
        if self.flatten {
            crate::output_staging::flat_relative(stored).into()
        } else {
            stored.into()
        }
    }

    /// Where outputs stage: the extraction storage, or in place the output directory.
    fn staging_root(&self) -> PathBuf {
        match &self.staging_at {
            Some(root) if !self.in_place => root.clone(),
            _ => self.out_dir.to_path_buf(),
        }
    }

    fn claim_flat_name(&mut self, relative: &Path, member: &[u8]) -> crate::Result<()> {
        if !self.flatten {
            return Ok(());
        }
        self.flat_names
            .claim(relative, member, self.overwrite)
            .map_err(|error| refused_output(error, member))
    }

    /// Whether a later member may land where an earlier one did: beside it,
    /// or over it when flattening or [`Self::overwrite_repeats`] allows.
    fn repeats_allowed(&self) -> bool {
        self.overwrite == OverwritePolicy::Rename
            || ((self.flatten || self.overwrite_repeats)
                && self.overwrite == OverwritePolicy::Always)
    }

    /// Where a member goes, refusing a symlink on the way. With the output
    /// directory open by descriptor, also what is there now; except in a
    /// directory this run made, where nothing was before it began. There a
    /// path this run used already is caught as it is reserved, or as it is
    /// published, which refuses anything else put there meanwhile.
    fn checked_destination(
        &mut self,
        relative: &Path,
    ) -> crate::Result<(PathBuf, Option<TreeEntry>)> {
        let mut publisher = self.publisher.state();
        let Some(tree) = publisher.tree()? else {
            return Ok((
                crate::filename::checked_output_path(self.out_dir, relative)?,
                None,
            ));
        };
        // Skipping existing files needs to see this run's own directories.
        let entry = if self.skip_existing {
            tree.lstat(relative)?
        } else {
            tree.lstat_unless_created(relative)?
        };
        match entry {
            TreeEntry::Symlink => Err(crate::Error::UnsafePath(
                "unsafe archive path crosses symlink",
            )),
            entry => Ok((self.out_dir.join(relative), Some(entry))),
        }
    }

    /// Whether a member is left unwritten: not selected, or kept out by an existing file,
    /// including one an earlier member is writing.
    fn passed_over(
        &mut self,
        meta: &crate::ExtractedEntryMeta,
        destination: &Path,
        existing: Option<&TreeEntry>,
    ) -> bool {
        if self
            .selected
            .as_ref()
            .is_some_and(|selected| !selected(meta))
        {
            return true;
        }
        let kept = self.skip_existing
            && !meta.is_directory
            && (self.planned_paths.contains(destination)
                || match existing {
                    Some(entry) => *entry != TreeEntry::Missing,
                    None => fs::symlink_metadata(destination).is_ok(),
                });
        self.kept_existing += usize::from(kept);
        kept
    }

    fn reserve_output_path(&mut self, path: PathBuf) -> crate::Result<()> {
        if !self.planned_paths.insert(path)
            && !((self.flatten || self.overwrite_repeats)
                && self.overwrite != OverwritePolicy::Never)
        {
            return Err(crate::Error::InvalidHeader(
                "multiple archive entries map to the same output path",
            ));
        }
        Ok(())
    }

    /// Checks a member may stage for `destination`, and readies the
    /// [`Self::staging_root`] it stages under. `existing` is what the output
    /// tree found at `destination`; without a tree, the checks go by path.
    fn prepare_staged_path(
        &mut self,
        destination: &Path,
        directory: bool,
        existing: Option<&TreeEntry>,
    ) -> crate::Result<()> {
        if !directory
            && self.overwrite == OverwritePolicy::Never
            && match existing {
                Some(entry) => *entry != TreeEntry::Missing,
                None => fs::symlink_metadata(destination).is_ok(),
            }
        {
            // As publishing it would find, if it opened before the
            // directory there was made.
            if let Some(TreeEntry::Directory(identity)) = existing {
                if self.publisher.state().made_here(identity) {
                    return Err(crate::Error::InvalidHeader(
                        "multiple archive entries map to the same output path",
                    ));
                }
            }
            return Err(self.already_exists(
                destination,
                std::io::Error::new(std::io::ErrorKind::AlreadyExists, "File exists"),
            ));
        }
        if self.in_place {
            // A collision would otherwise overwrite an earlier member before any check.
            let ours = |identity: &FileIdentity| {
                // A directory a walk made for an earlier member's path is
                // the run's own, but a directory member may land on it.
                if directory {
                    self.publisher.state().published(identity)
                } else {
                    self.publisher.state().made_here(identity)
                }
            };
            let ours = match existing {
                Some(TreeEntry::Directory(identity) | TreeEntry::Other(identity)) => ours(identity),
                Some(_) => false,
                None => FileIdentity::of(destination).is_ok_and(|identity| ours(&identity)),
            };
            if ours && !self.repeats_allowed() {
                return Err(crate::Error::InvalidHeader(
                    "multiple archive entries map to the same output path",
                ));
            }
            return Ok(());
        }
        if self.staging_at.is_none() {
            let staging = ExtractionStaging::new(self.out_dir)?;
            self.staging_at = Some(staging.root.clone());
            if let Some(out_tree) = self.publisher.state().tree()? {
                self.staging_tree = OutputTree::open(&staging.root)?;
                if let Some(staging_tree) = &self.staging_tree {
                    out_tree.forbid(staging_tree.identity());
                }
            }
            let by_descriptor = self.staging_tree.is_some();
            self.publisher.state().start_staging(staging, by_descriptor);
        }
        // The output tree refused the storage on its walk to the destination.
        if existing.is_none() {
            let publisher = self.publisher.state();
            let staging = publisher.staging().expect("staging exists");
            staging.reject_alias(destination)?;
        }
        let root = self.staging_at.as_deref().expect("staging exists");
        let relative = destination
            .strip_prefix(self.out_dir)
            .map_err(|_| crate::Error::InvalidHeader("unsafe archive path"))?;
        if destination.starts_with(root) {
            return Err(crate::Error::InvalidHeader(
                "archive path conflicts with extraction storage",
            ));
        }
        // With a staging tree nothing stages at its own path: publishing
        // finds any collision.
        if self.staging_tree.is_none() {
            let staged = root.join(relative);
            let collides = match fs::symlink_metadata(&staged) {
                Ok(metadata) => {
                    !metadata.is_dir()
                        || !directory
                        || self
                            .staged_directories
                            .contains(&FileIdentity::of(&staged)?)
                }
                Err(_) => false,
            };
            if collides {
                return Err(crate::Error::InvalidHeader(
                    "multiple archive entries map to the same output path",
                ));
            }
        }
        Ok(())
    }

    /// Opens a member at its destination, relative to the output directory
    /// opened by descriptor, by the overwrite policy. Never follows a
    /// symlink, and never writes through a hard link or anything but a
    /// regular file. `existing` is what [`Self::checked_destination`] found
    /// there. Returns where it was opened.
    fn open_in_place(
        &mut self,
        relative: &Path,
        destination: PathBuf,
        meta: &crate::ExtractedEntryMeta,
        existing: Option<&TreeEntry>,
    ) -> crate::Result<(PathBuf, Pending, Box<dyn Write + Send>)> {
        let mut publisher = self.publisher.state();
        let tree = publisher.opened_tree().expect("opened by in_place_tree");
        let refuse = |error| staged::refused_path(error, &meta.name);
        if meta.is_directory {
            let identity = tree.create_dirs(relative).map_err(refuse)?;
            return Ok((
                destination,
                Pending::InPlaceDirectory(identity),
                Box::new(std::io::sink()),
            ));
        }
        let (dir, dir_identity) = tree.parent_dir(relative).map_err(refuse)?;
        // Nothing was in a directory this run made before it began: a name
        // taken there was taken by this run, or by something racing it.
        let fresh = tree.created(&dir_identity);
        // Later checks take the state again.
        drop(publisher);
        let name = relative.file_name().expect("output path has a name");
        let mode = staged::file_create_mode(meta, self.restore_modes);
        let repeated =
            || crate::Error::InvalidHeader("multiple archive entries map to the same output path");
        // Only `Always` opens what is there, so only it needs to know which
        // files this run wrote.
        let tracked = self.overwrite == OverwritePolicy::Always && !self.repeats_allowed();
        let (path, file, created_mode, identity) = match self.overwrite {
            OverwritePolicy::Never => match dir.create_file(name, mode) {
                Ok(file) => (destination, file, Some(mode), None),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    // In a directory this run made, another member's
                    // output, as publishing a staged file would say.
                    // Elsewhere, what the checks before opening would have
                    // said, had it been there then.
                    if fresh {
                        return Err(repeated());
                    }
                    return Err(match dir.entry(name)? {
                        TreeEntry::Symlink => refuse(crate::Error::UnsafePath(
                            "unsafe archive path crosses symlink",
                        )),
                        TreeEntry::Directory(identity)
                            if self.publisher.state().made_here(&identity) =>
                        {
                            repeated()
                        }
                        _ => self.already_exists(&destination, error),
                    });
                }
                Err(error) => return Err(error.into()),
            },
            OverwritePolicy::Rename => {
                let (path, file) =
                    dir.create_numbered(&destination, mode, self.publisher.state().renames())?;
                (path, file, Some(mode), None)
            }
            OverwritePolicy::Always => {
                let created = match existing {
                    Some(TreeEntry::Missing) => match dir.create_file(name, mode) {
                        Ok(file) => Some(file),
                        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                            if fresh && tracked {
                                return Err(repeated());
                            }
                            None
                        }
                        Err(error) => return Err(error.into()),
                    },
                    _ => None,
                };
                match created {
                    Some(file) => {
                        let identity = tracked
                            .then(|| crate::output_tree::file_identity(&file))
                            .transpose()?;
                        (destination, file, Some(mode), identity)
                    }
                    None => {
                        let opened = dir.open_in_place(name, mode)?;
                        if tracked && self.publisher.state().made_here(&opened.identity) {
                            return Err(repeated());
                        }
                        if opened.len > 0 {
                            opened.file.set_len(0)?;
                        }
                        (destination, opened.file, None, Some(opened.identity))
                    }
                }
            }
        };
        let (writer, done) = crate::output_tree::HeldFile::new(file);
        let pending = Pending::InPlace(InPlace {
            file: done,
            dir: dir_identity,
            created_mode,
            identity,
        });
        Ok((path, pending, Box::new(writer)))
    }

    /// `Never`'s refusal of what is at `destination`, with the hint if there is one.
    fn already_exists(&self, destination: &Path, error: std::io::Error) -> crate::Error {
        match self.exists_hint {
            Some(hint) => std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("{} already exists{hint}", destination.display()),
            )
            .into(),
            None => error.into(),
        }
    }

    /// Staged outputs are always new files; in-place ones follow the caller's policy.
    fn staged_policy(&self) -> OverwritePolicy {
        if self.in_place {
            self.overwrite
        } else {
            OverwritePolicy::Never
        }
    }

    fn record_staged_path(&mut self, path: &Path, directory: bool) -> crate::Result<()> {
        if directory {
            self.staged_directories.insert(FileIdentity::of(path)?);
        }
        Ok(())
    }

    /// Move every settled staged output to its destination. Publishing as
    /// they settle keeps verified members when a later one fails and holds
    /// few members in staging.
    fn publish_verified(&mut self) -> crate::Result<()> {
        for output in self.unpublished.drain(..self.settled) {
            self.publisher.queue(output);
        }
        self.settled = 0;
        self.publisher.publish_failure()
    }

    /// As [`Self::publish_verified`], once everything queued is in place:
    /// a run that ends early still publishes what verified, and says why it could not.
    pub fn publish_verified_and_wait(&mut self) -> crate::Result<()> {
        let queued = self.publish_verified();
        self.publisher.wait_to_failure();
        queued?;
        self.publisher.publish_failure()
    }

    /// A run that ended well still fails on a member published since its last
    /// open, as it would have at that open had it published there.
    pub fn queued_failure(&mut self) -> crate::Result<()> {
        self.publisher.wait_to_failure();
        self.publisher.publish_failure()
    }

    /// Publish the final member once the whole extraction call has succeeded.
    pub fn publish(mut self) -> crate::Result<Vec<ExtractedOutput>> {
        self.publish_verified()?;
        self.publisher.finish()
    }
}

#[cfg(test)]
mod tests;

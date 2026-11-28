use crate::filename::{native_str, relative_path};
use crate::output_staging::{create_symlink, OverwritePolicy, RenameCounters};
use crate::{ArchiveFamily, Error, ExtractedLink, Result};
use std::borrow::Cow;
use std::collections::HashMap;
use std::ffi::OsString;
use std::fs;
use std::path::{Component, Path, PathBuf};

/// A RAR5 name as native bytes: `/` is its only separator, so other hosts' backslashes become `_`.
pub fn rar50_native_name(name: &[u8], unix_host: bool) -> Vec<u8> {
    if cfg!(unix) && unix_host {
        return crate::filename::decode_rar50(name).into_owned();
    }
    name.iter()
        .map(|&byte| if byte == b'\\' { b'_' } else { byte })
        .collect()
}

fn native_target(target: &[u8], family: ArchiveFamily, unix_host: bool) -> Cow<'_, [u8]> {
    // Legacy targets are native Unix bytes, not member names.
    if family == ArchiveFamily::Rar50Plus {
        Cow::Owned(rar50_native_name(target, unix_host))
    } else {
        Cow::Borrowed(target)
    }
}

pub fn is_legacy_symlink_member(meta: &crate::ArchiveMemberMeta) -> bool {
    meta.family == ArchiveFamily::Rar15To40
        && meta.host_os.is_some_and(|host| {
            crate::extraction_links::is_legacy_symlink(host, meta.file_attr, meta.is_directory)
        })
}

pub fn extract_arriving_with_links<V, F, L>(
    first: &crate::Archive,
    volumes: V,
    options: crate::ArchiveReadOptions<'_>,
    mut open: F,
    mut link: L,
) -> Result<()>
where
    V: IntoIterator<Item = Result<crate::Archive>>,
    V::IntoIter: Send,
    F: FnMut(&crate::ExtractedEntryMeta) -> Result<Box<dyn std::io::Write>>,
    L: FnMut(&crate::ExtractedEntryMeta, ExtractedLink<'_>) -> Result<()>,
{
    first.extract_arriving(volumes, options, &mut open, Some(&mut link))
}

/// Extracts a RAR 5 archive as [`crate::Archive::extract_with_links`] does,
/// except that outputs are `Send`: a member's output can be written and closed
/// on a worker thread, and members after it opened before it is verified.
///
/// `settled(meta, verified)` follows every call to `open`, on the calling
/// thread and in archive order: `true` once that member is written, verified
/// and its output dropped, `false` when the open or the member failed, before
/// the member error handler hears of it. An error from `settled` is the
/// member's own. A link is reported once every member opened before it has
/// settled, and before any member after it is opened. Only a member that has
/// settled `true` is verified; when the call fails, those opened and not
/// settled are not.
pub fn extract_rar50_settled_with_links<F, L, S>(
    archive: &crate::rar50::Archive,
    options: crate::ArchiveReadOptions<'_>,
    mut open: F,
    mut link: L,
    mut settled: S,
) -> Result<()>
where
    F: FnMut(&crate::ExtractedEntryMeta) -> Result<Box<dyn std::io::Write + Send>>,
    L: FnMut(&crate::ExtractedEntryMeta, ExtractedLink<'_>) -> Result<()>,
    S: FnMut(&crate::ExtractedEntryMeta, bool) -> Result<()>,
{
    let _cap = crate::parallel::ThreadCap::set(options.threads);
    options.check_cancelled()?;
    archive.extract_settled(
        options,
        &mut |meta| open(&crate::rar50_meta(meta)),
        &mut |meta, redirection| {
            crate::extraction_links::emit_rar50_link(meta, redirection, &mut link)
        },
        &mut |meta, verified| settled(&crate::rar50_meta(meta), verified),
    )
}

/// How a member [`extract_settled`] opened ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Settled {
    /// Written, verified, and its writer dropped.
    Verified,
    /// Its open or the member failed; what it delivered isn't its own.
    Failed,
    /// Failed under [`crate::ArchiveReadOptions::salvage`], and the member
    /// error handler carried on past it: keep what it delivered.
    KeptBroken,
}

/// What [`extract_settled`] extracts.
#[derive(Debug, Clone, Copy)]
pub enum SettledSource<'a> {
    Archive(&'a crate::Archive),
    /// In order, starting with the first.
    Volumes(&'a [crate::Archive]),
}

/// Chooses members by index in archive order; a member split across volumes counts once.
pub type Select<'a> = dyn Fn(usize, &crate::ArchiveMember) -> bool + 'a;

/// [`extract_rar50_settled_with_links`] for every family and volume sets, so outputs need only the settle protocol; under salvage a member settles once the handler has answered.
pub fn extract_settled<F, L, S>(
    source: SettledSource<'_>,
    options: crate::ArchiveReadOptions<'_>,
    select: Option<&Select<'_>>,
    open: F,
    link: L,
    settled: S,
) -> Result<()>
where
    F: FnMut(&crate::ExtractedEntryMeta) -> Result<Box<dyn std::io::Write + Send>>,
    L: FnMut(&crate::ExtractedEntryMeta, ExtractedLink<'_>) -> Result<()>,
    S: FnMut(&crate::ExtractedEntryMeta, Settled) -> Result<()> + Send,
{
    if let (SettledSource::Archive(crate::Archive::Rar50Plus(archive)), None, false) =
        (source, select, options.salvage)
    {
        return extract_rar50_settling_all(archive, options, open, link, settled);
    }
    settle_walk(
        options,
        open,
        link,
        settled,
        |read, state, open, link| match (source, select) {
            (SettledSource::Archive(archive), Some(select)) => {
                extract_selected(archive, read, select, state, open, link)
            }
            (SettledSource::Archive(archive), None) => archive.extract_with_links(read, open, link),
            (SettledSource::Volumes(volumes), select) => {
                let chosen =
                    std::cell::RefCell::new(select.map(|select| Chosen::new(volumes, select)));
                let chosen = |name: &[u8]| {
                    chosen
                        .borrow_mut()
                        .as_mut()
                        .is_none_or(|chosen| chosen.advance_to(name))
                };
                crate::extract_volumes_with_links(
                    volumes,
                    read,
                    |meta| {
                        if chosen(&meta.name) {
                            open(meta)
                        } else {
                            Ok(Box::new(std::io::sink()))
                        }
                    },
                    |meta, made| {
                        if chosen(&meta.name) {
                            link(meta, made)
                        } else {
                            Ok(())
                        }
                    },
                )
            }
        },
    )
}

pub type OpenOutput<'a> =
    dyn FnMut(&crate::ExtractedEntryMeta) -> Result<Box<dyn std::io::Write>> + 'a;
pub type MakeLink<'a> = dyn FnMut(&crate::ExtractedEntryMeta, ExtractedLink<'_>) -> Result<()> + 'a;

/// [`extract_settled`]'s settling for a walk it doesn't drive, such as arriving volumes; members open one at a time, as writing in place needs.
pub fn settle_in_order<F, L, S, R>(
    options: crate::ArchiveReadOptions<'_>,
    open: F,
    link: L,
    settled: S,
    run: R,
) -> Result<()>
where
    F: FnMut(&crate::ExtractedEntryMeta) -> Result<Box<dyn std::io::Write + Send>>,
    L: FnMut(&crate::ExtractedEntryMeta, ExtractedLink<'_>) -> Result<()>,
    S: FnMut(&crate::ExtractedEntryMeta, Settled) -> Result<()> + Send,
    R: for<'r> FnOnce(
        crate::ArchiveReadOptions<'r>,
        &mut OpenOutput<'_>,
        &mut MakeLink<'_>,
    ) -> Result<()>,
{
    settle_walk(options, open, link, settled, |read, _, open, link| {
        run(read, open, link)
    })
}

fn settle_walk<F, L, S, R>(
    options: crate::ArchiveReadOptions<'_>,
    mut open: F,
    mut link: L,
    settled: S,
    run: R,
) -> Result<()>
where
    F: FnMut(&crate::ExtractedEntryMeta) -> Result<Box<dyn std::io::Write + Send>>,
    L: FnMut(&crate::ExtractedEntryMeta, ExtractedLink<'_>) -> Result<()>,
    S: FnMut(&crate::ExtractedEntryMeta, Settled) -> Result<()> + Send,
    R: for<'r> FnOnce(
        crate::ArchiveReadOptions<'r>,
        &std::sync::Mutex<Settling<S>>,
        &mut OpenOutput<'_>,
        &mut MakeLink<'_>,
    ) -> Result<()>,
{
    let state = std::sync::Mutex::new(Settling {
        settled,
        opened: None,
        legacy_link: None,
    });
    let caller = options.member_errors;
    let salvage = options.salvage;
    let handler = |member: &crate::ArchiveMember, error: &Error| {
        let caller = caller.expect("installed only over the caller's handler");
        let opened = lock(&state).opened_failed(&member.meta.name)?;
        if opened && !salvage {
            lock(&state).settle(Settled::Failed)?;
        }
        let action = (caller.0)(member, error)?;
        if opened && salvage {
            let kept = action == crate::ExtractionErrorAction::Continue
                && !matches!(
                    error.kind(),
                    crate::ErrorKind::PasswordRequired | crate::ErrorKind::BadPassword
                );
            lock(&state).settle(if kept {
                Settled::KeptBroken
            } else {
                Settled::Failed
            })?;
        }
        Ok(action)
    };
    let read = match caller {
        Some(_) => options.with_member_error_handler(&handler),
        None => options,
    };
    let mut open = |meta: &crate::ExtractedEntryMeta| {
        let mut state = lock(&state);
        state.settle(Settled::Verified)?;
        state.opened = Some(meta.clone());
        drop(state);
        open(meta).map(|writer| writer as Box<dyn std::io::Write>)
    };
    let mut link = |meta: &crate::ExtractedEntryMeta, made: ExtractedLink<'_>| {
        lock(&state).settle(Settled::Verified)?;
        link(meta, made)
    };
    let result = run(read, &state, &mut open, &mut link);
    let mut state = state.into_inner().expect("settling lock poisoned");
    match &result {
        Ok(()) => state.settle(Settled::Verified)?,
        Err(error) => {
            // A later member's error means the one still open verified.
            let outcome = match (
                crate::output_staging::failed_entry_name(error),
                &state.opened,
            ) {
                (Some(failed), Some(opened)) if failed != opened.name.as_slice() => {
                    Settled::Verified
                }
                _ => Settled::Failed,
            };
            // The extraction's own error wins.
            let _ = state.settle(outcome);
        }
    }
    result
}

/// Settles what the write lane left open when the call fails, so every member opened settles.
fn extract_rar50_settling_all<F, L, S>(
    archive: &crate::rar50::Archive,
    options: crate::ArchiveReadOptions<'_>,
    mut open: F,
    link: L,
    settled: S,
) -> Result<()>
where
    F: FnMut(&crate::ExtractedEntryMeta) -> Result<Box<dyn std::io::Write + Send>>,
    L: FnMut(&crate::ExtractedEntryMeta, ExtractedLink<'_>) -> Result<()>,
    S: FnMut(&crate::ExtractedEntryMeta, Settled) -> Result<()>,
{
    let opened = std::cell::RefCell::new(std::collections::VecDeque::new());
    let settled = std::cell::RefCell::new(settled);
    let result = extract_rar50_settled_with_links(
        archive,
        options,
        |meta| {
            opened.borrow_mut().push_back(meta.clone());
            open(meta)
        },
        link,
        |meta, verified| {
            opened.borrow_mut().pop_front();
            let outcome = if verified {
                Settled::Verified
            } else {
                Settled::Failed
            };
            (settled.borrow_mut())(meta, outcome)
        },
    );
    if result.is_err() {
        for meta in opened.take() {
            // The extraction's own error wins.
            let _ = (settled.borrow_mut())(&meta, Settled::Failed);
        }
    }
    result
}

struct Settling<S> {
    settled: S,
    /// The member opened last, until it settles.
    opened: Option<crate::ExtractedEntryMeta>,
    /// A selected legacy symbolic link's target, made into a link once it verifies.
    legacy_link: Option<(
        crate::ExtractedEntryMeta,
        std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
    )>,
}

impl<S: FnMut(&crate::ExtractedEntryMeta, Settled) -> Result<()>> Settling<S> {
    fn settle(&mut self, outcome: Settled) -> Result<()> {
        match self.opened.take() {
            Some(meta) => (self.settled)(&meta, outcome),
            None => Ok(()),
        }
    }

    /// Whether the member named failed after opening; a different one still open has verified.
    fn opened_failed(&mut self, name: &[u8]) -> Result<bool> {
        if self
            .legacy_link
            .as_ref()
            .is_some_and(|(meta, _)| meta.name == name)
        {
            self.legacy_link = None;
        }
        match &self.opened {
            Some(opened) if opened.name == name => Ok(true),
            Some(_) => self.settle(Settled::Verified).map(|()| false),
            None => Ok(false),
        }
    }
}

/// Matched by name: a member that fails before it opens reports nothing to count by.
struct Chosen {
    members: Vec<(Vec<u8>, bool)>,
    next: usize,
}

impl Chosen {
    fn new(volumes: &[crate::Archive], select: &Select<'_>) -> Self {
        let members = volumes
            .iter()
            .flat_map(crate::Archive::members)
            .filter(|member| !member.meta.is_split_before)
            .enumerate()
            .map(|(index, member)| (member.meta.name.clone(), select(index, &member)))
            .collect();
        Self { members, next: 0 }
    }

    fn advance_to(&mut self, name: &[u8]) -> bool {
        let Some(found) = self.members[self.next..]
            .iter()
            .position(|(member, _)| member == name)
        else {
            return false;
        };
        self.next += found + 1;
        self.members[self.next - 1].1
    }
}

/// [`crate::Archive::extract_with_control`] skips what's left out and asks once the previous member verified.
fn extract_selected<S: FnMut(&crate::ExtractedEntryMeta, Settled) -> Result<()>>(
    archive: &crate::Archive,
    read: crate::ArchiveReadOptions<'_>,
    select: &Select<'_>,
    state: &std::sync::Mutex<Settling<S>>,
    open: &mut dyn FnMut(&crate::ExtractedEntryMeta) -> Result<Box<dyn std::io::Write>>,
    link: &mut dyn FnMut(&crate::ExtractedEntryMeta, ExtractedLink<'_>) -> Result<()>,
) -> Result<()> {
    let chosen: Vec<bool> = archive
        .members()
        .enumerate()
        .map(|(index, member)| select(index, &member))
        .collect();
    let Some(last) = chosen.iter().rposition(|&chosen| chosen) else {
        return Ok(());
    };
    let solid = archive.is_solid();
    let link_verified =
        |link: &mut dyn FnMut(&crate::ExtractedEntryMeta, ExtractedLink<'_>) -> Result<()>| {
            let Some((meta, target)) = lock(state).legacy_link.take() else {
                return Ok(());
            };
            let target = std::mem::take(&mut *lock(&target));
            check_legacy_symlink_target(&meta.name, target.len() as u64, Some(&target))?;
            link(
                &meta,
                ExtractedLink::Symlink {
                    target: &target,
                    directory: false,
                },
            )
        };
    let mut index = 0;
    let result = archive.extract_with_control(read, |member| {
        link_verified(&mut *link)?;
        lock(state).settle(Settled::Verified)?;
        let current = index;
        index += 1;
        if current > last {
            return Ok(crate::ExtractionDecision::Stop);
        }
        let meta = &member.meta;
        if meta.is_redirection {
            if let (
                true,
                crate::ArchiveMemberDetail::Rar50Plus {
                    redirection: Some(redirection),
                    ..
                },
            ) = (chosen[current], &member.detail)
            {
                link(&member_meta(member), ExtractedLink::rar50(redirection)?)?;
            }
            return Ok(crate::ExtractionDecision::Skip);
        }
        if !chosen[current] {
            return Ok(if solid && !meta.is_directory {
                crate::ExtractionDecision::Extract(Box::new(std::io::sink()))
            } else {
                crate::ExtractionDecision::Skip
            });
        }
        if is_legacy_symlink_member(meta) {
            check_legacy_symlink_target(&meta.name, meta.unpacked_size, None)?;
            let target = std::sync::Arc::default();
            lock(state).legacy_link = Some((member_meta(member), std::sync::Arc::clone(&target)));
            return Ok(crate::ExtractionDecision::Extract(Box::new(LinkTarget(
                target,
            ))));
        }
        open(&member_meta(member)).map(crate::ExtractionDecision::Extract)
    });
    result?;
    link_verified(link)
}

/// Collects a legacy symlink member's data, which is its target.
struct LinkTarget(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for LinkTarget {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .expect("link target lock poisoned")
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn member_meta(member: &crate::ArchiveMember) -> crate::ExtractedEntryMeta {
    let meta = &member.meta;
    let mut extracted = crate::ExtractedEntryMeta::new(
        meta.name.clone(),
        meta.modification_time(),
        meta.file_attr,
        meta.is_directory,
    )
    .with_attr_source(meta.attr_source());
    extracted.name_is_unicode = member.name_is_unicode();
    extracted
}

fn lock<T>(state: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    state.lock().expect("settling lock poisoned")
}

pub fn check_legacy_symlink_target(name: &[u8], size: u64, target: Option<&[u8]>) -> Result<()> {
    if size > crate::extraction_links::LEGACY_TARGET_LIMIT {
        return Err(
            Error::InvalidHeader("legacy symbolic link target exceeds 64 KiB")
                .at_entry(name.to_vec(), "reading link target"),
        );
    }
    match target {
        Some(target) => crate::extraction_links::validate_legacy_target(target, name),
        None => Ok(()),
    }
}

/// What the containment check needs to know about the output directory: which
/// paths already there are symbolic links, and where they point. A link already
/// in the output can carry a new one out of it, so the check follows them.
pub trait OutputTree {
    /// The target of the symbolic link at `path`, or `None` when nothing is
    /// there or it is not a link.
    fn read_link(&self, path: &Path) -> std::io::Result<Option<PathBuf>>;
}

/// The output directory as the filesystem has it.
pub struct Filesystem;

impl OutputTree for Filesystem {
    fn read_link(&self, path: &Path) -> std::io::Result<Option<PathBuf>> {
        match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_symlink() => fs::read_link(path).map(Some),
            Ok(_) => Ok(None),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                ) =>
            {
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }
}

/// Where `link` at `relative` under `root` points, or `None` for a symlink to skip because it could leave `root`.
pub fn link_target(
    root: &Path,
    relative: &Path,
    meta: &crate::ExtractedEntryMeta,
    link: ExtractedLink<'_>,
    family: ArchiveFamily,
    flat: bool,
) -> Result<Option<PathBuf>> {
    link_target_in(&Filesystem, root, relative, meta, link, family, flat)
}

/// [`link_target`], asking `tree` about the links already in the output, for a
/// caller that cannot reach the filesystem itself.
pub fn link_target_in(
    tree: &dyn OutputTree,
    root: &Path,
    relative: &Path,
    meta: &crate::ExtractedEntryMeta,
    link: ExtractedLink<'_>,
    family: ArchiveFamily,
    flat: bool,
) -> Result<Option<PathBuf>> {
    let unix_host = meta.attr_source == crate::AttrSource::Unix;
    match link {
        // Hard links and copies name an earlier member, so they follow member-name rules.
        ExtractedLink::HardLink { target } | ExtractedLink::FileCopy { target } => {
            relative_path(&native_target(target, family, unix_host), false)
                .map(Some)
                .map_err(|_| Error::InvalidHeader("unsafe archive redirection target"))
        }
        ExtractedLink::Symlink { target, .. } | ExtractedLink::Junction { target } if flat => {
            Ok(flat_symlink_target(tree, root, target, family, unix_host)?)
        }
        ExtractedLink::Symlink { target, .. } | ExtractedLink::Junction { target } => Ok(
            safe_symlink_target(tree, root, relative, target, family, unix_host)?,
        ),
    }
}

/// A bare name can still lead out through a link already in `root`, as in nested output.
fn flat_symlink_target(
    tree: &dyn OutputTree,
    root: &Path,
    target: &[u8],
    family: ArchiveFamily,
    unix_host: bool,
) -> std::io::Result<Option<PathBuf>> {
    let Some(name) = flat_target(target, family, unix_host) else {
        return Ok(None);
    };
    let step = Step::Down(name.clone().into_os_string());
    Ok(stays_inside(tree, root, Vec::new(), &[step])?.then_some(name))
}

/// Flat output has no directories, so only a symlink to a bare name still means what it did.
fn flat_target(target: &[u8], family: ArchiveFamily, unix_host: bool) -> Option<PathBuf> {
    // Other hosts' RAR5 backslashes were separators, though the native name turns them into `_`.
    if family == ArchiveFamily::Rar50Plus && !unix_host && target.contains(&b'\\') {
        return None;
    }
    let target = native_target(target, family, unix_host);
    if target.contains(&0)
        || target
            .iter()
            .any(|&byte| std::path::is_separator(byte.into()))
        || (target.len() >= 2 && target[0].is_ascii_alphabetic() && target[1] == b':')
    {
        return None;
    }
    let path = Path::new(native_str(&target).ok()?);
    let mut components = path.components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(name)), None) => Some(PathBuf::from(name)),
        _ => None,
    }
}

fn safe_symlink_target(
    tree: &dyn OutputTree,
    root: &Path,
    relative: &Path,
    target: &[u8],
    family: ArchiveFamily,
    unix_host: bool,
) -> std::io::Result<Option<PathBuf>> {
    let target = native_target(target, family, unix_host);
    if target.contains(&0)
        || (target.len() >= 2 && target[0].is_ascii_alphabetic() && target[1] == b':')
    {
        return Ok(None);
    }
    let Ok(text) = native_str(&target) else {
        return Ok(None);
    };
    let Some(steps) = path_steps(Path::new(text)) else {
        return Ok(None);
    };
    if steps.is_empty() {
        return Ok(None);
    }
    let directory = relative.parent().unwrap_or(Path::new(""));
    let Some(start) = path_steps(directory) else {
        return Ok(None);
    };
    let start = start
        .into_iter()
        .map(|step| match step {
            Step::Down(name) => Some(name),
            Step::Up => None,
        })
        .collect::<Option<Vec<_>>>();
    let Some(start) = start else {
        return Ok(None);
    };
    if !stays_inside(tree, root, start, &steps)? {
        return Ok(None);
    }
    Ok(Some(
        steps
            .into_iter()
            .map(|step| match step {
                Step::Up => OsString::from(".."),
                Step::Down(name) => name,
            })
            .collect(),
    ))
}

#[derive(Clone)]
enum Step {
    Up,
    Down(OsString),
}

fn path_steps(path: &Path) -> Option<Vec<Step>> {
    path.components()
        .filter_map(|component| match component {
            Component::CurDir => None,
            Component::ParentDir => Some(Some(Step::Up)),
            Component::Normal(name) => Some(Some(Step::Down(name.to_os_string()))),
            Component::RootDir | Component::Prefix(_) => Some(None),
        })
        .collect()
}

/// `..` may only leave a directory holding the link or a followed link: any other could still become a link.
fn stays_inside(
    tree: &dyn OutputTree,
    root: &Path,
    start: Vec<OsString>,
    steps: &[Step],
) -> std::io::Result<bool> {
    let mut at = start;
    let mut stable = at.len();
    let mut todo: Vec<Step> = steps.iter().rev().cloned().collect();
    let mut hops = 0;
    while let Some(step) = todo.pop() {
        match step {
            Step::Up => {
                if at.is_empty() || at.len() > stable {
                    return Ok(false);
                }
                at.pop();
                stable = at.len();
            }
            Step::Down(name) => {
                at.push(name);
                let path: PathBuf = std::iter::once(root.as_os_str())
                    .chain(at.iter().map(OsString::as_os_str))
                    .collect();
                if let Some(next) = tree.read_link(&path)? {
                    hops += 1;
                    if hops > 40 {
                        return Ok(false);
                    }
                    let Some(next) = path_steps(&next) else {
                        return Ok(false);
                    };
                    at.pop();
                    stable = at.len();
                    todo.extend(next.into_iter().rev());
                }
            }
        }
    }
    Ok(true)
}

/// What a link member made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MadeLink {
    /// Keeps its own metadata: setting it would follow the link.
    Symlink,
    /// Shares its source's mode.
    HardLink,
    /// Whether the mode it was asked for went on through its own handle.
    Copy { mode_set: bool },
}

impl MadeLink {
    /// Whether it is a file whose metadata should be restored.
    pub fn is_file(self) -> bool {
        self != Self::Symlink
    }
}

/// Returns the created path and what it is. A file copy is given
/// `copy_mode` through its own handle.
#[allow(clippy::too_many_arguments)]
pub fn create_link_output(
    out_dir: &Path,
    relative: &Path,
    target: &Path,
    link: ExtractedLink<'_>,
    overwrite: OverwritePolicy,
    created_paths: &HashMap<PathBuf, PathBuf>,
    renames: &mut RenameCounters,
    copy_mode: Option<u32>,
) -> Result<(PathBuf, MadeLink)> {
    // Resolve hard-link/copy sources before touching an existing destination.
    let source = match link {
        ExtractedLink::HardLink { .. } | ExtractedLink::FileCopy { .. } => {
            Some(link_source_path(target, created_paths)?)
        }
        ExtractedLink::Symlink { .. } | ExtractedLink::Junction { .. } => None,
    };
    let checked = |root: &Path| {
        crate::filename::checked_output_path(root, relative).map_err(|error| match error {
            Error::UnsafePath(message) => Error::InvalidHeader(message),
            other => other,
        })
    };
    let mut out_path = checked(out_dir)?;
    fs::create_dir_all(
        out_path
            .parent()
            .expect("validated output path has a parent"),
    )?;
    out_path = checked(out_dir)?;
    prepare_link_destination(&out_path, overwrite)?;
    // Each refuses an existing destination, so `Rename` can claim a free name.
    let create = |out_path: &Path| match link {
        ExtractedLink::Symlink { directory, .. } => {
            create_symlink(target, out_path, directory).map(|()| MadeLink::Symlink)
        }
        ExtractedLink::Junction { .. } => {
            create_symlink(target, out_path, true).map(|()| MadeLink::Symlink)
        }
        ExtractedLink::HardLink { .. } => {
            fs::hard_link(source.expect("source checked above"), out_path)
                .map(|()| MadeLink::HardLink)
        }
        ExtractedLink::FileCopy { .. } => {
            // Open the source first, so a vanished one leaves no empty destination.
            let mut input = fs::File::open(source.expect("source checked above"))?;
            let mut output = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(out_path)?;
            std::io::copy(&mut input, &mut output)?;
            let mode_set = copy_mode
                .is_some_and(|mode| crate::output_modes::set_file_mode(&output, mode).is_ok());
            Ok(MadeLink::Copy { mode_set })
        }
    };
    if overwrite == OverwritePolicy::Rename {
        return renames.claim(&out_path, create);
    }
    let made = create(&out_path)?;
    Ok((out_path, made))
}

pub fn link_source_path<'a>(
    target: &Path,
    created_paths: &'a HashMap<PathBuf, PathBuf>,
) -> Result<&'a Path> {
    created_paths
        .get(target)
        .map(PathBuf::as_path)
        .ok_or(Error::InvalidHeader(
            "RAR 5 redirection target was not extracted earlier",
        ))
}

fn prepare_link_destination(path: &Path, overwrite: OverwritePolicy) -> std::io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => match overwrite {
            OverwritePolicy::Never => Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "file exists",
            )),
            OverwritePolicy::Rename => Ok(()),
            OverwritePolicy::Always => {
                if metadata.is_dir() {
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

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::symlink;

    /// An output directory described rather than on disk, as the wasm engine sees it.
    struct Described(HashMap<PathBuf, PathBuf>);

    impl OutputTree for Described {
        fn read_link(&self, path: &Path) -> std::io::Result<Option<PathBuf>> {
            Ok(self.0.get(path).cloned())
        }
    }

    #[test]
    fn a_described_tree_is_followed_like_the_filesystem() {
        let meta = crate::ExtractedEntryMeta::new(b"x".to_vec(), None, 0o120777, false)
            .with_attr_source(crate::AttrSource::Unix);
        let link = ExtractedLink::Symlink {
            target: b"dir/x",
            directory: false,
        };
        let target = |tree: &dyn OutputTree| {
            link_target_in(
                tree,
                Path::new(""),
                Path::new("x"),
                &meta,
                link,
                ArchiveFamily::Rar50Plus,
                false,
            )
            .unwrap()
        };
        // Nothing there yet: the target stays inside.
        assert_eq!(
            target(&Described(HashMap::new())),
            Some(PathBuf::from("dir/x"))
        );
        // `dir` is already a link out of the root, so following the target leaves it.
        let escape = Described(HashMap::from([(PathBuf::from("dir"), PathBuf::from(".."))]));
        assert_eq!(target(&escape), None);
        let inside = Described(HashMap::from([(
            PathBuf::from("dir"),
            PathBuf::from("sub"),
        )]));
        assert_eq!(target(&inside), Some(PathBuf::from("dir/x")));
    }

    fn check(root: &Path, link: &str, target: &[u8]) -> Option<PathBuf> {
        safe_symlink_target(
            &Filesystem,
            root,
            Path::new(link),
            target,
            ArchiveFamily::Rar50Plus,
            true,
        )
        .unwrap()
    }

    fn redirection(link: ExtractedLink<'_>) -> Result<Option<PathBuf>> {
        let meta = crate::ExtractedEntryMeta::new(b"a/copy".to_vec(), None, 0o100644, false)
            .with_attr_source(crate::AttrSource::Unix);
        link_target_in(
            &Described(HashMap::new()),
            Path::new(""),
            Path::new("a/copy"),
            &meta,
            link,
            ArchiveFamily::Rar50Plus,
            false,
        )
    }

    #[test]
    fn hard_links_and_copies_name_members_and_refuse_anything_else() {
        // They point at an earlier member, so they take member-name rules, not
        // a symbolic link's: the target is a path from the root, `.` is
        // dropped, and nothing may climb or be absolute.
        for link in [
            |target| ExtractedLink::HardLink { target },
            |target| ExtractedLink::FileCopy { target },
        ] as [fn(&[u8]) -> ExtractedLink<'_>; 2]
        {
            assert_eq!(
                redirection(link(b"b/original")).unwrap(),
                Some(PathBuf::from("b/original"))
            );
            assert_eq!(
                redirection(link(b"./b/original")).unwrap(),
                Some(PathBuf::from("b/original"))
            );
            for target in [
                b"../outside".as_slice(),
                b"b/../../outside",
                b"/etc/passwd",
                b"C:/Windows",
                b"",
                b"b\0x",
            ] {
                assert!(
                    matches!(
                        redirection(link(target)),
                        Err(Error::InvalidHeader("unsafe archive redirection target"))
                    ),
                    "{target:?}"
                );
            }
        }
    }

    #[test]
    fn current_directory_steps_are_dropped_before_the_containment_check() {
        let root = crate::scratch::case("links-current-directory");
        fs::create_dir(root.join("a")).unwrap();
        assert_eq!(
            check(&root, "a/sym", b"./local.txt"),
            Some(PathBuf::from("local.txt"))
        );
        assert_eq!(
            check(&root, "a/sym", b"./.././c/./target.txt"),
            Some(PathBuf::from("../c/target.txt"))
        );
        // Dropping `.` must not hide a climb out of the root.
        assert_eq!(check(&root, "a/sym", b"./../.././outside"), None);
        // Nothing left to point at.
        assert_eq!(check(&root, "a/sym", b"./."), None);
    }

    #[test]
    fn a_link_whose_own_path_is_not_a_plain_member_path_is_refused() {
        // Member names are made safe before this, so these cannot come from an
        // archive; the check still refuses to measure from such a place.
        let root = crate::scratch::case("links-own-path");
        assert_eq!(check(&root, "../sym", b"x"), None);
        assert_eq!(check(&root, "a/../sym", b"x"), None);
        assert_eq!(check(&root, "/abs/sym", b"x"), None);
    }

    #[test]
    fn legacy_symlink_targets_are_capped_at_64_kib() {
        let limit = crate::extraction_links::LEGACY_TARGET_LIMIT;
        assert!(check_legacy_symlink_target(b"link", limit, None).is_ok());
        let error = check_legacy_symlink_target(b"link", limit + 1, None).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("legacy symbolic link target exceeds 64 KiB"),
            "{error}"
        );
    }

    #[test]
    fn flat_extraction_keeps_only_bare_targets() {
        let flat = |target: &[u8], unix_host: bool| {
            flat_target(target, ArchiveFamily::Rar50Plus, unix_host)
        };
        assert_eq!(flat(b"local.txt", true), Some(PathBuf::from("local.txt")));
        // A Unix host's backslash is a literal character.
        assert_eq!(flat(br"odd\name", true), Some(PathBuf::from(r"odd\name")));
        for target in [
            b"../c/target.txt".as_slice(),
            b"c/target.txt",
            b"/etc/hosts",
            b"..",
            b".",
            b"",
            b"C:x",
        ] {
            assert_eq!(flat(target, true), None, "{target:?}");
        }
        for target in [
            br"..\c\target.txt".as_slice(),
            br"C:\x",
            br"\??\C:\x",
            b"C:x",
        ] {
            assert_eq!(flat(target, false), None, "{target:?}");
        }
    }

    #[test]
    fn targets_that_stay_inside_keep_their_parent_components() {
        let root = crate::scratch::case("links-inside");
        fs::create_dir(root.join("a")).unwrap();
        assert_eq!(
            check(&root, "a/sym.txt", b"../c/target.txt"),
            Some(PathBuf::from("../c/target.txt"))
        );
        assert_eq!(
            check(&root, "a/near.txt", b"local.txt"),
            Some(PathBuf::from("local.txt"))
        );
        assert_eq!(check(&root, "a/up", b".."), Some(PathBuf::from("..")));
    }

    #[test]
    fn targets_that_climb_out_or_are_absolute_are_refused() {
        let root = crate::scratch::case("links-outside");
        fs::create_dir(root.join("a")).unwrap();
        for target in [
            b"../../outside".as_slice(),
            b"/etc/passwd",
            b"C:/Windows",
            b"",
        ] {
            assert_eq!(check(&root, "a/sym", target), None, "{target:?}");
        }
        assert_eq!(check(&root, "sym", b".."), None);
        let windows = safe_symlink_target(
            &Filesystem,
            &root,
            Path::new("sym"),
            br"C:\Windows",
            ArchiveFamily::Rar50Plus,
            false,
        )
        .unwrap();
        assert_eq!(windows, None);
        let legacy = safe_symlink_target(
            &Filesystem,
            &root,
            Path::new("a/sym"),
            b"../../outside",
            ArchiveFamily::Rar15To40,
            true,
        )
        .unwrap();
        assert_eq!(legacy, None);
    }

    #[test]
    fn a_chain_through_an_earlier_link_cannot_climb_out() {
        let root = crate::scratch::case("links-chain");
        fs::create_dir(root.join("a")).unwrap();
        symlink("..", root.join("a/up")).unwrap();
        // Lexically root/a, but through the real a/up it is root's parent.
        assert_eq!(check(&root, "x", b"a/up/.."), None);
        assert_eq!(check(&root, "x", b"a/up/a"), Some(PathBuf::from("a/up/a")));
    }

    #[test]
    fn parent_components_after_a_missing_or_new_directory_are_refused() {
        let root = crate::scratch::case("links-later");
        fs::create_dir(root.join("empty")).unwrap();
        // Either could still become a link, so `..` out of it is refused.
        assert_eq!(check(&root, "x", b"missing/../y"), None);
        assert_eq!(check(&root, "x", b"empty/../y"), None);
        fs::create_dir_all(root.join("a/b")).unwrap();
        // `a/b/m -> ..` later would take this to root's parent.
        assert_eq!(check(&root, "a/b/k", b"m/../../y"), None);
        assert_eq!(
            check(&root, "a/b/k", b"../../y"),
            Some(PathBuf::from("../../y"))
        );
    }

    #[test]
    fn flat_targets_do_not_follow_existing_links_out_of_the_root() {
        let root = crate::scratch::case("links-flat-existing");
        symlink("/", root.join("escape")).unwrap();
        symlink("local", root.join("inside")).unwrap();
        let flat = |target: &[u8]| {
            flat_symlink_target(&Filesystem, &root, target, ArchiveFamily::Rar50Plus, true).unwrap()
        };
        assert_eq!(flat(b"escape"), None);
        assert_eq!(flat(b"inside"), Some(PathBuf::from("inside")));
        assert_eq!(flat(b"local"), Some(PathBuf::from("local")));
    }

    #[test]
    fn existing_links_that_leave_the_root_are_not_followed() {
        let root = crate::scratch::case("links-existing");
        symlink("/", root.join("escape")).unwrap();
        symlink("loop", root.join("loop")).unwrap();
        assert_eq!(check(&root, "x", b"escape/etc"), None);
        assert_eq!(check(&root, "x", b"escape"), None);
        assert_eq!(check(&root, "x", b"loop"), None);
    }
}

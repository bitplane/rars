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

pub fn rar50_link(redirection: &crate::rar50::FileRedirection) -> Result<ExtractedLink<'_>> {
    ExtractedLink::rar50(redirection)
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
        |meta| open(&crate::rar50_meta(meta)),
        |meta, redirection| crate::extraction_links::emit_rar50_link(meta, redirection, &mut link),
        |meta, verified| settled(&crate::rar50_meta(meta), verified),
    )
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

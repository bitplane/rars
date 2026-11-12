use crate::filename::{native_str, relative_path};
use crate::output_staging::{claim_free_name, create_symlink, OverwritePolicy};
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

/// Where `link` at `relative` under `root` points, or `None` for a symlink to skip because it could leave `root`.
pub fn link_target(
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
            Ok(flat_target(target, family, unix_host))
        }
        ExtractedLink::Symlink { target, .. } | ExtractedLink::Junction { target } => Ok(
            safe_symlink_target(root, relative, target, family, unix_host)?,
        ),
    }
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
    if !stays_inside(root, start, &steps)? {
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
fn stays_inside(root: &Path, start: Vec<OsString>, steps: &[Step]) -> std::io::Result<bool> {
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
                match fs::symlink_metadata(&path) {
                    Ok(metadata) if metadata.file_type().is_symlink() => {
                        hops += 1;
                        let Some(next) = (hops <= 40).then(|| fs::read_link(&path)).transpose()?
                        else {
                            return Ok(false);
                        };
                        let Some(next) = path_steps(&next) else {
                            return Ok(false);
                        };
                        at.pop();
                        stable = at.len();
                        todo.extend(next.into_iter().rev());
                    }
                    Ok(_) => {}
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                        ) => {}
                    Err(error) => return Err(error),
                }
            }
        }
    }
    Ok(true)
}

/// Returns the created path, and whether it is a file whose metadata should be restored.
pub fn create_link_output(
    out_dir: &Path,
    relative: &Path,
    target: &Path,
    link: ExtractedLink<'_>,
    overwrite: OverwritePolicy,
    created_paths: &HashMap<PathBuf, PathBuf>,
) -> Result<(PathBuf, bool)> {
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
            create_symlink(target, out_path, directory).map(|()| false)
        }
        ExtractedLink::Junction { .. } => create_symlink(target, out_path, true).map(|()| false),
        ExtractedLink::HardLink { .. } => {
            fs::hard_link(source.expect("source checked above"), out_path).map(|()| true)
        }
        ExtractedLink::FileCopy { .. } => {
            // Open the source first, so a vanished one leaves no empty destination.
            let mut input = fs::File::open(source.expect("source checked above"))?;
            let mut output = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(out_path)?;
            std::io::copy(&mut input, &mut output)?;
            Ok(true)
        }
    };
    if overwrite == OverwritePolicy::Rename {
        return claim_free_name(&out_path, create);
    }
    let file = create(&out_path)?;
    Ok((out_path, file))
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

    fn check(root: &Path, link: &str, target: &[u8]) -> Option<PathBuf> {
        safe_symlink_target(
            root,
            Path::new(link),
            target,
            ArchiveFamily::Rar50Plus,
            true,
        )
        .unwrap()
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
            &root,
            Path::new("sym"),
            br"C:\Windows",
            ArchiveFamily::Rar50Plus,
            false,
        )
        .unwrap();
        assert_eq!(windows, None);
        let legacy = safe_symlink_target(
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
    fn existing_links_that_leave_the_root_are_not_followed() {
        let root = crate::scratch::case("links-existing");
        symlink("/", root.join("escape")).unwrap();
        symlink("loop", root.join("loop")).unwrap();
        assert_eq!(check(&root, "x", b"escape/etc"), None);
        assert_eq!(check(&root, "x", b"escape"), None);
        assert_eq!(check(&root, "x", b"loop"), None);
    }
}

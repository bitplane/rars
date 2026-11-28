use crate::{AttrSource, ExtractedEntryMeta};
use std::fs;
use std::path::{Path, PathBuf};

/// Platform-free so a wasm caller, which sets modes itself, can use it.
pub fn restored_mode(meta: &ExtractedEntryMeta) -> Option<u32> {
    const FILE_ATTRIBUTE_READONLY: u64 = 0x01;

    let attr = meta.file_attr;
    match meta.attr_source {
        // A DOS attribute word says nothing about permissions except whether
        // the entry is read-only. Everything else is already right: the file
        // was created 0666 & ~umask and the directory 0777 & ~umask, which is
        // what the reference leaves behind, so only read-only needs acting on
        // and only on files.
        AttrSource::Dos => {
            (!meta.is_directory && attr & FILE_ATTRIBUTE_READONLY != 0).then_some(0o444)
        }
        // A st_mode is applied verbatim, but only when it carries file-type
        // bits. Without them the value is not a mode, and stripping a file to
        // whatever the low bits happen to say is worse than leaving it.
        AttrSource::Unix if attr & 0o170000 != 0 => Some((attr & 0o777) as u32),
        // Missing type bits and unknown (including future) hosts leave modes unchanged.
        _ => None,
    }
}

/// [`restored_mode`] where this build sets modes, which is only on Unix.
pub fn applied_mode(meta: &ExtractedEntryMeta) -> Option<u32> {
    if cfg!(unix) {
        restored_mode(meta)
    } else {
        None
    }
}

/// A mode denying its owner read waits for the end, so later members can copy from the file.
pub fn waits_for_end(mode: u32) -> bool {
    mode & 0o400 == 0
}

/// The mode a member's file takes through its own handle, before it is published.
pub fn early_mode(meta: &ExtractedEntryMeta) -> Option<u32> {
    applied_mode(meta).filter(|&mode| !waits_for_end(mode))
}

/// The permission bits a member's file is created with: its [`early_mode`], else 0666.
pub fn create_mode(meta: &ExtractedEntryMeta) -> u32 {
    early_mode(meta).unwrap_or(0o666)
}

/// Modes set by path once extraction ends: files first, then directories
/// deepest first, so a parent's mode can't deny access to what is under it.
#[derive(Debug, Default)]
pub struct PathModes {
    files: Vec<(PathBuf, u32)>,
    directories: Vec<(PathBuf, u32)>,
}

impl PathModes {
    pub fn record(&mut self, path: PathBuf, meta: &ExtractedEntryMeta) {
        let Some(mode) = applied_mode(meta) else {
            return;
        };
        if meta.is_directory {
            self.directories.push((path, mode));
        } else {
            self.files.push((path, mode));
        }
    }

    pub fn restore(mut self) -> std::io::Result<()> {
        self.directories
            .sort_by_cached_key(|(path, _)| std::cmp::Reverse(path.components().count()));
        for (path, mode) in self.files.iter().chain(&self.directories) {
            set_mode(path, *mode)?;
        }
        Ok(())
    }
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> std::io::Result<()> {
    Ok(())
}

#[cfg(unix)]
pub fn set_file_mode(file: &fs::File, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
pub fn set_file_mode(_file: &fs::File, _mode: u32) -> std::io::Result<()> {
    Err(std::io::ErrorKind::Unsupported.into())
}

/// Whether `file` has exactly the permission bits `mode`.
#[cfg(unix)]
pub fn has_mode(file: &fs::File, mode: u32) -> bool {
    use std::os::unix::fs::PermissionsExt;
    file.metadata()
        .is_ok_and(|metadata| metadata.permissions().mode() & 0o7777 == mode)
}

#[cfg(not(unix))]
pub fn has_mode(_file: &fs::File, _mode: u32) -> bool {
    false
}

/// Whether creating a file in one directory with given permission bits
/// gives it exactly those bits, for each set of bits a file there was created
/// with: the umask or a default ACL may clear some. Learnt from the first file
/// created with each, so the others need no change when they are kept. Only
/// sound while the process's umask stays put.
#[derive(Clone)]
#[cfg_attr(not(unix), derive(Default))]
pub struct CreatedModes {
    #[cfg(unix)]
    known: std::sync::Arc<[std::sync::atomic::AtomicU8]>,
}

#[cfg(unix)]
impl Default for CreatedModes {
    fn default() -> Self {
        Self {
            known: (0..=0o7777).map(|_| Default::default()).collect(),
        }
    }
}

impl CreatedModes {
    // Not known yet is 0, as each starts.
    #[cfg(unix)]
    const KEPT: u8 = 1;
    #[cfg(unix)]
    const CHANGED: u8 = 2;

    /// Whether `file`, created here with the permission bits `mode` and not
    /// changed since, has them.
    #[cfg(unix)]
    pub fn kept(&self, file: &fs::File, mode: u32) -> bool {
        use std::sync::atomic::Ordering;
        let Some(known) = self.known.get(mode as usize) else {
            return false;
        };
        match known.load(Ordering::Relaxed) {
            Self::KEPT => true,
            Self::CHANGED => false,
            _ => {
                let kept = has_mode(file, mode);
                known.store(
                    if kept { Self::KEPT } else { Self::CHANGED },
                    Ordering::Relaxed,
                );
                kept
            }
        }
    }

    #[cfg(not(unix))]
    pub fn kept(&self, _file: &fs::File, _mode: u32) -> bool {
        false
    }
    /// Gives `file`, created here with the permission bits `mode`, exactly those bits.
    pub fn apply(&self, file: &fs::File, mode: u32) -> std::io::Result<()> {
        if self.kept(file, mode) {
            return Ok(());
        }
        set_file_mode(file, mode)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(source: AttrSource, attr: u64, directory: bool) -> ExtractedEntryMeta {
        ExtractedEntryMeta::new(b"entry".to_vec(), None, attr, directory).with_attr_source(source)
    }

    #[test]
    fn modes_follow_attribute_source_and_type_bits() {
        for (source, attr, directory, expected) in [
            (AttrSource::Dos, 0, false, None),
            (AttrSource::Dos, 1, false, Some(0o444)),
            (AttrSource::Dos, 1, true, None),
            (AttrSource::Unix, 0o777, false, None),
            (AttrSource::Unix, 0o100754, false, Some(0o754)),
            (AttrSource::Unix, 0o040700, true, Some(0o700)),
            (AttrSource::Unix, u64::MAX, false, Some(0o777)),
            (AttrSource::Unknown, u64::MAX, false, None),
        ] {
            assert_eq!(
                restored_mode(&meta(source, attr, directory)),
                expected,
                "{source:?} {attr:o} directory={directory}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn files_are_created_with_their_mode_unless_it_denies_the_owner_read() {
        let unix = |attr| meta(AttrSource::Unix, attr, false);
        assert_eq!(create_mode(&unix(0o100750)), 0o750);
        assert_eq!(create_mode(&unix(0o100200)), 0o666);
        assert_eq!(create_mode(&meta(AttrSource::Unknown, 0, false)), 0o666);
        assert_eq!(early_mode(&unix(0o100750)), Some(0o750));
        assert_eq!(early_mode(&unix(0o100200)), None);
        assert_eq!(early_mode(&meta(AttrSource::Dos, 1, false)), Some(0o444));
        assert!(waits_for_end(0o200));
        assert!(!waits_for_end(0o400));
    }

    #[cfg(unix)]
    #[test]
    fn modes_set_by_path_respect_attribute_source_and_type_bits() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;
        let dir = crate::scratch::case("output-modes-by-path");
        for (source, attr, directory, expected) in [
            (AttrSource::Dos, 0, false, 0o640),
            (AttrSource::Dos, 1, false, 0o444),
            (AttrSource::Dos, 1, true, 0o640),
            (AttrSource::Unix, 0o777, false, 0o640),
            (AttrSource::Unix, 0o100754, false, 0o754),
            (AttrSource::Unix, u64::MAX, false, 0o777),
            (AttrSource::Unknown, u64::MAX, false, 0o640),
        ] {
            let path = dir.join("entry");
            if path.is_dir() {
                fs::remove_dir(&path).unwrap();
            } else if path.exists() {
                fs::remove_file(&path).unwrap();
            }
            if directory {
                fs::create_dir(&path).unwrap();
            } else {
                fs::write(&path, b"payload").unwrap();
            }
            fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
            let mut modes = PathModes::default();
            modes.record(path.clone(), &meta(source, attr, directory));
            modes.restore().unwrap();
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                expected
            );
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        }
    }

    #[cfg(unix)]
    #[test]
    fn created_modes_tell_kept_bits_from_cleared_ones() {
        use std::os::unix::fs::PermissionsExt;
        let dir = crate::scratch::case("output-modes-created");
        let modes = CreatedModes::default();
        let file = std::fs::File::create(dir.join("file")).unwrap();
        set_file_mode(&file, 0o640).unwrap();
        assert!(has_mode(&file, 0o640));
        assert!(modes.kept(&file, 0o640));
        // The first file decides for every later one created with those bits.
        set_file_mode(&file, 0o600).unwrap();
        assert!(modes.kept(&file, 0o640));
        assert!(!modes.kept(&file, 0o644));
        assert_eq!(
            file.metadata().unwrap().permissions().mode() & 0o7777,
            0o600
        );
    }

    #[cfg(unix)]
    #[test]
    fn created_files_end_with_exactly_their_mode() {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let dir = crate::scratch::case("output-modes-apply");
        let modes = CreatedModes::default();
        // 0777 loses bits to any umask but 0; 0600 to none but the strictest.
        for (index, mode) in [0o777, 0o600, 0o777, 0o600].into_iter().enumerate() {
            let file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(mode)
                .open(dir.join(index.to_string()))
                .unwrap();
            modes.apply(&file, mode).unwrap();
            assert_eq!(
                file.metadata().unwrap().permissions().mode() & 0o7777,
                mode,
                "{index}"
            );
        }
    }
}

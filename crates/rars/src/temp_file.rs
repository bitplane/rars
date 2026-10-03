//! Temporary creation shared by private spools and archive publication.

use crate::{Error, Result};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum TemporaryKind {
    Spool,
    #[cfg(any(feature = "write", feature = "recovery"))]
    Archive,
}

pub(crate) fn next_sequence() -> u64 {
    SEQUENCE.fetch_add(1, Ordering::Relaxed)
}

pub(crate) fn create_with_sequence<C>(
    directory: &Path,
    admit: impl FnMut(usize) -> Result<C>,
    next_sequence: impl FnMut() -> u64,
) -> Result<(PathBuf, File, C)> {
    create_named_with_sequence(TemporaryKind::Spool, directory, admit, next_sequence)
}

pub(crate) fn create_named_with_sequence<C>(
    kind: TemporaryKind,
    directory: &Path,
    mut admit: impl FnMut(usize) -> Result<C>,
    mut next_sequence: impl FnMut() -> u64,
) -> Result<(PathBuf, File, C)> {
    let (prefix, overflow, collision) = match kind {
        TemporaryKind::Spool => (
            ".rars-spool",
            "spool path capacity overflows",
            "could not allocate a unique rars spool file",
        ),
        #[cfg(any(feature = "write", feature = "recovery"))]
        TemporaryKind::Archive => (
            ".rars-writing",
            "temporary path capacity overflows",
            "could not allocate a unique archive temporary file",
        ),
    };
    for _ in 0..128 {
        let sequence = next_sequence();
        // Both prefixes, a process ID and u64 hex sequence fit this buffer.
        let mut name = [0u8; 64];
        let mut name_writer = std::io::Cursor::new(&mut name[..]);
        write!(
            name_writer,
            "{prefix}-{}-{sequence:016x}",
            std::process::id()
        )
        .expect("temporary name fits its fixed buffer");
        let name_len = name_writer.position() as usize;
        let name = std::str::from_utf8(&name[..name_len]).expect("ASCII temporary name");
        let capacity = directory
            .as_os_str()
            .len()
            .checked_add(1 + name_len)
            .ok_or(Error::InvalidArgument(overflow))?;
        let path_charge = admit(capacity)?;
        let mut path = PathBuf::with_capacity(capacity);
        path.push(directory);
        path.push(name);
        let mut options = File::options();
        options.write(true).create_new(true);
        if kind == TemporaryKind::Spool {
            options.read(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                // Temporary storage can hold plaintext before encryption or after
                // decryption, so keep its creation mode private.
                options.mode(0o600);
            }
        }
        match options.open(&path) {
            Ok(file) => {
                return Ok((path, file, path_charge));
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Err(std::io::Error::new(std::io::ErrorKind::AlreadyExists, collision).into())
}

/// An uncharged file owner. The reader applies its own logical disk quota.
pub(crate) struct TemporaryFile {
    path: PathBuf,
    file: Option<File>,
}

impl TemporaryFile {
    pub(crate) fn create(directory: &Path) -> Result<Self> {
        let (path, file, ()) = create_with_sequence(directory, |_| Ok(()), next_sequence)?;
        Ok(Self {
            path,
            file: Some(file),
        })
    }
}

impl Read for TemporaryFile {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        self.file
            .as_mut()
            .expect("temporary file is present")
            .read(bytes)
    }
}
impl Write for TemporaryFile {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.file
            .as_mut()
            .expect("temporary file is present")
            .write(bytes)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.file
            .as_mut()
            .expect("temporary file is present")
            .flush()
    }
}
impl Seek for TemporaryFile {
    fn seek(&mut self, from: SeekFrom) -> std::io::Result<u64> {
        self.file
            .as_mut()
            .expect("temporary file is present")
            .seek(from)
    }
}
impl Drop for TemporaryFile {
    fn drop(&mut self) {
        self.file = None;
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(all(test, unix, any(feature = "write", feature = "recovery")))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn creation_permissions_preserve_private_spools_and_default_archives() {
        let root = crate::scratch::case("temporary-creation-permissions");
        let reference = File::create(root.join("reference")).unwrap();
        let default_mode = reference.metadata().unwrap().permissions().mode() & 0o777;
        for kind in [TemporaryKind::Spool, TemporaryKind::Archive] {
            let (_, mut file, ()) =
                create_named_with_sequence(kind, &root, |_| Ok(()), || 0).unwrap();
            let mode = file.metadata().unwrap().permissions().mode() & 0o777;
            if kind == TemporaryKind::Spool {
                assert_eq!(mode & 0o077, 0, "plaintext spool must remain private");
                file.write_all(b"payload").unwrap();
                file.rewind().unwrap();
                let mut bytes = Vec::new();
                file.read_to_end(&mut bytes).unwrap();
                assert_eq!(bytes, b"payload");
            } else {
                assert_eq!(
                    mode, default_mode,
                    "publication retains ordinary archive permissions"
                );
                assert!(
                    file.read(&mut [0]).is_err(),
                    "publication file remains write-only"
                );
            }
        }
    }
}

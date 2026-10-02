//! Private temporary files shared by reader scratch and writer spools.

use crate::{Error, Result};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub(crate) fn next_sequence() -> u64 {
    SEQUENCE.fetch_add(1, Ordering::Relaxed)
}

pub(crate) fn create_with_sequence<C>(
    directory: &Path,
    mut admit: impl FnMut(usize) -> Result<C>,
    mut next_sequence: impl FnMut() -> u64,
) -> Result<(PathBuf, File, C)> {
    for _ in 0..128 {
        let sequence = next_sequence();
        // Prefix (12), u32 process ID (at most 10), separator (1), and
        // u64 hex sequence (16) total at most 39 bytes in this buffer.
        let mut name = [0u8; 64];
        let mut name_writer = std::io::Cursor::new(&mut name[..]);
        write!(
            name_writer,
            ".rars-spool-{}-{sequence:016x}",
            std::process::id()
        )
        .expect("spool name fits its fixed buffer");
        let name_len = name_writer.position() as usize;
        let name = std::str::from_utf8(&name[..name_len]).expect("ASCII spool name");
        let capacity = directory
            .as_os_str()
            .len()
            .checked_add(1 + name_len)
            .ok_or(Error::InvalidArgument("spool path capacity overflows"))?;
        let path_charge = admit(capacity)?;
        let mut path = PathBuf::with_capacity(capacity);
        path.push(directory);
        path.push(name);
        let mut options = File::options();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // Temporary storage can hold plaintext before encryption or after
            // decryption, so keep its creation mode private.
            options.mode(0o600);
        }
        match options.open(&path) {
            Ok(file) => {
                return Ok((path, file, path_charge));
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "could not allocate a unique rars spool file",
    )
    .into())
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

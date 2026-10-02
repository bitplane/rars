//! Temporary archive publication shared by writing and recovery repair.

use crate::{Error, Result};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

pub(crate) struct PendingArchive<C = ()> {
    pub(crate) path: Option<PathBuf>,
    _charge: C,
}

impl PendingArchive<()> {
    pub(crate) fn create(destination: &Path) -> Result<(Self, fs::File)> {
        Self::with_admission(destination, |_| Ok(()))
    }
}

impl<C> PendingArchive<C> {
    pub(crate) fn with_admission(
        destination: &Path,
        admit: impl FnMut(usize) -> Result<C>,
    ) -> Result<(Self, fs::File)> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        Self::create_with_sequence(destination, admit, || NEXT.fetch_add(1, Ordering::Relaxed))
    }

    pub(crate) fn create_with_sequence(
        destination: &Path,
        mut admit: impl FnMut(usize) -> Result<C>,
        mut next_sequence: impl FnMut() -> u64,
    ) -> Result<(Self, fs::File)> {
        for _ in 0..128 {
            let sequence = next_sequence();
            let mut name = [0u8; 64];
            let mut name_writer = std::io::Cursor::new(&mut name[..]);
            write!(
                name_writer,
                ".rars-writing-{}-{sequence:016x}",
                std::process::id()
            )
            .expect("fixed ASCII temporary name fits its buffer");
            let name_len = name_writer.position() as usize;
            let name = std::str::from_utf8(&name[..name_len]).expect("ASCII temporary name");
            let directory = destination.parent().unwrap_or_else(|| Path::new(""));
            let capacity = directory
                .as_os_str()
                .len()
                .checked_add(1 + name_len)
                .ok_or(Error::InvalidArgument("temporary path capacity overflows"))?;
            // Keep admission before allocation and hold its owner until this
            // pending archive is published or removed.
            let charge = admit(capacity)?;
            let mut path = PathBuf::with_capacity(capacity);
            path.push(directory);
            path.push(name);
            match fs::File::options().write(true).create_new(true).open(&path) {
                Ok(file) => {
                    return Ok((
                        Self {
                            path: Some(path),
                            _charge: charge,
                        },
                        file,
                    ))
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "could not allocate a unique archive temporary file",
        )
        .into())
    }
}

impl<C> Drop for PendingArchive<C> {
    fn drop(&mut self) {
        if let Some(path) = &self.path {
            let _ = fs::remove_file(path);
        }
    }
}

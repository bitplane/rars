//! Temporary archive publication shared by writing and recovery repair.

use crate::{Error, Result, WriterResources};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

pub(crate) struct PendingArchive {
    pub(crate) path: Option<PathBuf>,
    _charge: Option<crate::streaming::CapacityCharge>,
}

impl PendingArchive {
    pub(crate) fn create(destination: &Path) -> Result<(Self, fs::File)> {
        Self::with_resources(destination, &WriterResources::default())
    }
    pub(crate) fn with_resources(
        destination: &Path,
        resources: &WriterResources,
    ) -> Result<(Self, fs::File)> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        Self::with_sequence(destination, resources, || {
            NEXT.fetch_add(1, Ordering::Relaxed)
        })
    }

    pub(crate) fn with_sequence(
        destination: &Path,
        resources: &WriterResources,
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
            let mut charge = resources.execution_charge();
            if let Some(charge) = &mut charge {
                charge.grow_to(capacity as u64)?;
            }
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

impl Drop for PendingArchive {
    fn drop(&mut self) {
        if let Some(path) = &self.path {
            let _ = fs::remove_file(path);
        }
    }
}

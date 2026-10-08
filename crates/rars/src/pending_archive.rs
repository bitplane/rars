//! Temporary archive publication shared by writing and recovery repair.

use crate::Result;
use std::fs;
use std::path::{Path, PathBuf};

pub(crate) struct PendingArchive<C = ()> {
    pub(crate) path: Option<PathBuf>,
    _charge: C,
}

#[cfg(feature = "recovery")]
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
        use crate::atomic64::AtomicU64;
        use std::sync::atomic::Ordering;
        static NEXT: AtomicU64 = AtomicU64::new(0);
        Self::create_with_sequence(destination, admit, || NEXT.fetch_add(1, Ordering::Relaxed))
    }

    pub(crate) fn create_with_sequence(
        destination: &Path,
        admit: impl FnMut(usize) -> Result<C>,
        next_sequence: impl FnMut() -> u64,
    ) -> Result<(Self, fs::File)> {
        let directory = destination.parent().unwrap_or_else(|| Path::new(""));
        let (path, file, charge) = crate::temp_file::create_named_with_sequence(
            crate::temp_file::TemporaryKind::Archive,
            directory,
            admit,
            next_sequence,
        )?;
        Ok((
            Self {
                path: Some(path),
                _charge: charge,
            },
            file,
        ))
    }
}

impl<C> Drop for PendingArchive<C> {
    fn drop(&mut self) {
        if let Some(path) = &self.path {
            let _ = fs::remove_file(path);
        }
    }
}

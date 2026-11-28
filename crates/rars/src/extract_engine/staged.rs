use crate::output_modes::{applied_mode, create_mode, waits_for_end, CreatedModes};
use crate::output_staging::OverwritePolicy;
use crate::{Error, ExtractedEntryMeta};
use std::fs;
use std::path::{Path, PathBuf};

pub struct ExtractedOutput {
    pub name: Vec<u8>,
    /// The member's stored path, which flattening or renaming may move it from.
    pub stored: PathBuf,
    pub path: PathBuf,
    pub meta: ExtractedEntryMeta,
    pub restore_metadata: bool,
    /// Off when the engine ignores modes: times are still restored.
    pub restore_mode: bool,
    /// Off when the engine ignores times: modes are still restored.
    pub restore_time: bool,
}

pub(crate) fn open_output_writer(
    out_dir: &Path,
    relative: &Path,
    directory: bool,
    overwrite: OverwritePolicy,
    renames: &mut crate::output_staging::RenameCounters,
    unsafe_paths: UnsafePaths,
) -> crate::Result<(PathBuf, Box<dyn std::io::Write + Send>)> {
    let mut out_path = unsafe_paths.checked_output_path(out_dir, relative)?;
    if directory {
        fs::create_dir_all(&out_path)?;
        return Ok((out_path, Box::new(std::io::sink())));
    }
    fs::create_dir_all(
        out_path
            .parent()
            .expect("validated output path has a parent"),
    )?;
    out_path = unsafe_paths.checked_output_path(out_dir, relative)?;
    let (out_path, file) = crate::output_staging::open_in_place(&out_path, overwrite, renames)?;
    Ok((out_path, Box::new(file)))
}

pub fn restore_output_metadata(outputs: &[ExtractedOutput]) -> std::io::Result<()> {
    let restored: Vec<_> = outputs
        .iter()
        .filter(|output| output.restore_metadata)
        .collect();
    let mut times = crate::output_times::OutputTimes::new();
    for output in restored.iter().filter(|output| output.restore_time) {
        times.opened(output.path.clone(), &output.meta);
    }
    times.finish();
    times.restore()?;
    let mut modes = crate::output_modes::PathModes::default();
    for output in restored.into_iter().filter(|output| output.restore_mode) {
        modes.record(output.path.clone(), &output.meta);
    }
    modes.restore()
}

/// The modified time and mode a regular file can take before it is
/// published, or `None` when they wait for the end: a mode that denies its
/// owner reading would stop a later member copying from it.
pub(crate) fn early_file_metadata(output: &ExtractedOutput) -> Option<EarlyMetadata> {
    output
        .restore_metadata
        .then(|| early_metadata(&output.meta, output.restore_time, output.restore_mode))
        .flatten()
}

/// A file's modified time and mode, set before it is published.
pub(crate) type EarlyMetadata = (Option<std::time::SystemTime>, Option<u32>);

fn early_metadata(
    meta: &ExtractedEntryMeta,
    restore_time: bool,
    restore_mode: bool,
) -> Option<EarlyMetadata> {
    let mode = restore_mode.then(|| applied_mode(meta)).flatten();
    if mode.is_some_and(waits_for_end) {
        return None;
    }
    let modified = meta
        .modified
        .filter(|_| restore_time)
        .and_then(|time| std::time::SystemTime::try_from(time).ok());
    Some((modified, mode))
}

pub(crate) fn file_create_mode(meta: &ExtractedEntryMeta, restore_mode: bool) -> u32 {
    if restore_mode {
        create_mode(meta)
    } else {
        0o666
    }
}

/// A staged file, created and finished on whichever thread writes it. It is
/// created on its first write or flush, or as it is dropped, so the thread
/// that opens it pays for no system call. As it is closed it takes its early
/// metadata through its own descriptor; `closed` records what it did, and
/// publication sets anything it did not.
pub(crate) struct StagedFile {
    file: crate::output_tree::DeferredFile,
    early: Option<EarlyMetadata>,
    closed: std::sync::Arc<Closed>,
    created_modes: CreatedModes,
}

/// What a [`StagedFile`] did as it closed.
#[derive(Default)]
pub(crate) struct Closed {
    /// An empty member nothing wrote is created as it closes, which can fail unheard.
    pub(crate) created: std::sync::atomic::AtomicBool,
    pub(crate) early_set: std::sync::atomic::AtomicBool,
}

impl StagedFile {
    /// Created on the thread that opens it, when that thread also writes it: quicker than at first write.
    pub(crate) fn create(&mut self) -> std::io::Result<()> {
        self.file.file().map(drop)
    }

    /// A file to create as `name` in `dir` once it is first used.
    pub(crate) fn deferred(
        dir: crate::output_tree::FileDir,
        name: std::ffi::OsString,
        meta: &ExtractedEntryMeta,
        restore_time: bool,
        restore_mode: bool,
        created_modes: CreatedModes,
    ) -> (Self, std::sync::Arc<Closed>) {
        let closed = std::sync::Arc::<Closed>::default();
        let early = early_metadata(meta, restore_time, restore_mode);
        let staged = Self {
            file: crate::output_tree::DeferredFile::new(
                dir,
                name,
                file_create_mode(meta, restore_mode),
            ),
            early,
            closed: std::sync::Arc::clone(&closed),
            created_modes,
        };
        (staged, closed)
    }
}

impl std::io::Write for StagedFile {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.file.write(buf)
    }

    fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        self.file.write_all(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

impl Drop for StagedFile {
    fn drop(&mut self) {
        let early = self.early;
        let created_modes = self.created_modes.clone();
        // An empty member nothing flushed is still a file.
        let Ok(file) = self.file.file() else {
            return;
        };
        self.closed
            .created
            .store(true, std::sync::atomic::Ordering::Release);
        let Some((modified, mode)) = early else {
            return;
        };
        let set = (|| {
            if let Some(modified) = modified {
                file.set_modified(modified)?;
            }
            // Created with its early mode.
            if let Some(mode) = mode {
                created_modes.apply(file, mode)?;
            }
            std::io::Result::Ok(())
        })();
        self.closed
            .early_set
            .store(set.is_ok(), std::sync::atomic::Ordering::Release);
    }
}

/// How a member path that would leave the output directory is reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UnsafePaths {
    /// As a bad header, as every refusal the CLI reports is.
    AsBadHeader,
    /// As [`Error::UnsafePath`], as the library documents, after its stricter name check.
    AsUnsafe,
}

impl UnsafePaths {
    fn report(self, error: Error) -> Error {
        match (self, error) {
            (Self::AsBadHeader, Error::UnsafePath(message)) => Error::InvalidHeader(message),
            (_, error) => error,
        }
    }

    pub(crate) fn checked_output_path(self, out_dir: &Path, rel: &Path) -> crate::Result<PathBuf> {
        crate::filename::checked_output_path(out_dir, rel).map_err(|error| self.report(error))
    }

    /// Names the member, which the walks' own errors don't.
    pub(crate) fn refused(self, error: Error, name: &[u8]) -> Error {
        match error {
            Error::UnsafePath(_) => crate::output_staging::refused_output(self.report(error), name),
            other => other,
        }
    }
}

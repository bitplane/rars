//! Stored modified times for extracted outputs, set once extraction ends because writing into a directory moves its time.
//! Shared by the CLI and the Python binding; not part of the stable API.

use crate::timestamp::extracted_system_time;
use crate::{ArchiveFamily, ExtractedEntryMeta};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

#[derive(Debug, Default)]
pub struct OutputTimes {
    completed: Vec<OutputTime>,
    /// The latest output, which may still be failing; it waits for the next one or `finish`.
    current: Option<OutputTime>,
}

#[derive(Debug)]
struct OutputTime {
    path: PathBuf,
    modified: SystemTime,
    is_directory: bool,
}

impl OutputTimes {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records an output as it opens, which completes the one before it.
    pub fn opened(&mut self, path: PathBuf, family: ArchiveFamily, meta: &ExtractedEntryMeta) {
        self.finish();
        self.current =
            extracted_system_time(family, meta.file_time, meta.mtime_refinement).map(|modified| {
                OutputTime {
                    path,
                    modified,
                    is_directory: meta.is_directory,
                }
            });
    }

    /// Marks the latest output complete, once extraction has moved past it.
    pub fn finish(&mut self) {
        self.completed.extend(self.current.take());
    }

    /// Sets the completed outputs' times: files first, then directories deepest first.
    pub fn restore(&self) -> std::io::Result<()> {
        let mut outputs: Vec<_> = self.completed.iter().collect();
        outputs.sort_by_key(|output| {
            (
                output.is_directory,
                std::cmp::Reverse(output.path.components().count()),
            )
        });
        for output in outputs {
            set_modified_time(&output.path, output.modified)?;
        }
        Ok(())
    }
}

#[cfg(windows)]
pub fn set_modified_time(path: &Path, time: SystemTime) -> std::io::Result<()> {
    use std::os::windows::fs::OpenOptionsExt;

    const FILE_WRITE_ATTRIBUTES: u32 = 0x0100;
    // Required to open a directory handle at all.
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;

    std::fs::OpenOptions::new()
        .access_mode(FILE_WRITE_ATTRIBUTES)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)?
        .set_modified(time)
}

#[cfg(not(windows))]
pub fn set_modified_time(path: &Path, time: SystemTime) -> std::io::Result<()> {
    std::fs::File::open(path)?.set_modified(time)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    fn meta(seconds: u32, is_directory: bool) -> ExtractedEntryMeta {
        ExtractedEntryMeta::new(b"x".to_vec(), Some(seconds), 0, is_directory)
    }

    fn modified(path: &Path) -> SystemTime {
        std::fs::metadata(path).unwrap().modified().unwrap()
    }

    #[test]
    fn a_directory_keeps_its_time_after_files_are_written_into_it() {
        let root = crate::scratch::case("output-times-directory");
        let directory = root.join("directory");
        let file = directory.join("file");
        std::fs::create_dir(&directory).unwrap();
        let mut times = OutputTimes::new();
        times.opened(
            directory.clone(),
            ArchiveFamily::Rar50Plus,
            &meta(1_000, true),
        );
        std::fs::write(&file, b"x").unwrap();
        times.opened(file.clone(), ArchiveFamily::Rar50Plus, &meta(2_000, false));
        times.finish();

        times.restore().unwrap();

        assert_eq!(
            modified(&directory),
            UNIX_EPOCH + Duration::from_secs(1_000)
        );
        assert_eq!(modified(&file), UNIX_EPOCH + Duration::from_secs(2_000));
    }

    #[test]
    fn an_unfinished_output_keeps_its_written_time() {
        let root = crate::scratch::case("output-times-unfinished");
        let done = root.join("done");
        let failed = root.join("failed");
        std::fs::write(&done, b"x").unwrap();
        std::fs::write(&failed, b"x").unwrap();
        let written = modified(&failed);
        let mut times = OutputTimes::new();
        times.opened(done.clone(), ArchiveFamily::Rar50Plus, &meta(1_000, false));
        times.opened(
            failed.clone(),
            ArchiveFamily::Rar50Plus,
            &meta(2_000, false),
        );

        times.restore().unwrap();

        assert_eq!(modified(&done), UNIX_EPOCH + Duration::from_secs(1_000));
        assert_eq!(modified(&failed), written);
    }
}

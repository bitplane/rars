use std::path::PathBuf;

/// Opt-in disk scratch for large RAR5/7 compressed members.
///
/// Files are privately created in an existing caller-selected directory and
/// removed on drop (cleanup errors cannot be reported from Drop). Scratch may
/// contain decrypted data. The directory must remain trusted and available.
/// Bare WebAssembly rejects this disk policy; it never substitutes RAM storage.
///
/// ```no_run
/// # fn extract(archive: &rars::Archive) -> rars::Result<()> {
/// let scratch = rars::Rar50Scratch::new("/path/to/private/scratch", 4 * 1024 * 1024 * 1024)
///     .with_filter_memory_limit(8 * 1024 * 1024);
/// let options = rars::ArchiveReadOptions::new()
///     .with_rar50_buffered_decode_limit(1024 * 1024)
///     .with_rar50_scratch(&scratch);
/// archive.extract_to_with_options(options, |_| Ok(Box::new(std::io::sink())))?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct Rar50Scratch {
    pub(crate) directory: PathBuf,
    pub(crate) max_bytes: u64,
    pub(crate) filter_memory_limit: u64,
}

impl Rar50Scratch {
    /// Limits combined logical scratch-file lengths for one member, including
    /// raw output, transformed output and filter records. Files are released
    /// between members; filesystem allocation overhead is outside this quota.
    /// Admission reserves room for twice the declared member size. Filter
    /// records require an additional 24 bytes each as they are encountered.
    pub fn new(directory: impl Into<PathBuf>, max_bytes: u64) -> Self {
        Self {
            directory: directory.into(),
            max_bytes,
            filter_memory_limit: 8 * 1024 * 1024,
        }
    }

    /// Bounds temporary filter data (default 8 MiB). Each filter range requires
    /// at most twice its length; a larger range is refused before allocation.
    /// Dictionary/history, compressed blocks and fixed I/O buffers are separate.
    pub fn with_filter_memory_limit(mut self, bytes: u64) -> Self {
        self.filter_memory_limit = bytes;
        self
    }
}

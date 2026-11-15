use crate::{rar50, Archive, ArchiveReadOptions, Result};
use std::path::Path;
use std::sync::Arc;

/// Parses a volume set so its shared RAR 5 key is derived once, not once per volume.
pub struct ReadSession<'a> {
    options: ArchiveReadOptions<'a>,
    key_cache: Arc<rar50::Rar50KeyCache>,
}

impl<'a> ReadSession<'a> {
    /// Starts a session that parses every volume with `options`.
    pub fn new(options: ArchiveReadOptions<'a>) -> Self {
        Self {
            options,
            key_cache: Arc::default(),
        }
    }

    /// Continues a set from `first`, reusing the RAR 5 keys it has already derived.
    pub fn continuing(first: &Archive, options: ArchiveReadOptions<'a>) -> Self {
        let key_cache = match first {
            Archive::Rar50Plus(archive) => Arc::clone(&archive.key_cache),
            _ => Arc::default(),
        };
        Self { options, key_cache }
    }

    /// Parses one volume as [`ArchiveReader::read_path_with_options`] does.
    pub fn read_path(&mut self, path: impl AsRef<Path>) -> Result<Archive> {
        crate::ArchiveReader::read_path_cached(path, self.options, Arc::clone(&self.key_cache))
    }

    /// Parses one seekable volume as [`ArchiveReader::read_reader_with_options`] does.
    pub fn read_reader<R: std::io::Read + std::io::Seek + Send + 'static>(
        &mut self,
        reader: R,
    ) -> Result<Archive> {
        crate::ArchiveReader::read_reader_cached(reader, self.options, Arc::clone(&self.key_cache))
    }

    /// Parses one in-memory volume as [`ArchiveReader::read_owned_with_options`] does.
    pub fn read_owned(&mut self, input: Vec<u8>) -> Result<Archive> {
        crate::ArchiveReader::read_owned_cached(input, self.options, Arc::clone(&self.key_cache))
    }
}

impl std::fmt::Debug for ReadSession<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReadSession")
            .field("has_password", &self.options.password.is_some())
            .finish_non_exhaustive()
    }
}
